#include "tyche.h"
#include "nested.h"
#include "vmcs12.h"

#include <asm/desc.h>
#include <asm/virtext.h>
#include <asm/msr-index.h>

MODULE_LICENSE("GPL");

#define KVM_VM_CR0_ALWAYS_OFF (X86_CR0_NW | X86_CR0_CD)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR0_NE
#define KVM_VM_CR0_ALWAYS_ON \
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)

#define KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR4_VMXE
#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

#define MSR_IA32_RTIT_STATUS_MASK                                            \
	(~(RTIT_STATUS_FILTEREN | RTIT_STATUS_CONTEXTEN |                    \
	   RTIT_STATUS_TRIGGEREN | RTIT_STATUS_ERROR | RTIT_STATUS_STOPPED | \
	   RTIT_STATUS_BYTECNT))

/*
 * List of MSRs that can be directly passed to the guest.
 * In addition to these x2apic and PT MSRs are handled specially.
 */
static u32 vmx_possible_passthrough_msrs[MAX_POSSIBLE_PASSTHROUGH_MSRS] = {
	MSR_IA32_SPEC_CTRL,
	MSR_IA32_PRED_CMD,
	MSR_IA32_TSC,
#ifdef CONFIG_X86_64
	MSR_FS_BASE,
	MSR_GS_BASE,
	MSR_KERNEL_GS_BASE,
	MSR_IA32_XFD,
	MSR_IA32_XFD_ERR,
#endif
	MSR_IA32_SYSENTER_CS,
	MSR_IA32_SYSENTER_ESP,
	MSR_IA32_SYSENTER_EIP,
	MSR_CORE_C1_RES,
	MSR_CORE_C3_RESIDENCY,
	MSR_CORE_C6_RESIDENCY,
	MSR_CORE_C7_RESIDENCY,
};

bool __read_mostly enable_ept = 1;
module_param_named(ept, enable_ept, bool, S_IRUGO);

bool __read_mostly enable_unrestricted_guest = 1;
module_param_named(unrestricted_guest,
			enable_unrestricted_guest, bool, S_IRUGO);

/*
 * If nested=1, nested virtualization is supported, i.e., guests may use
 * VMX and be a hypervisor for its own guests. If nested=0, guests may not
 * use VMX instructions.
 */
static bool __read_mostly nested = 1;
module_param(nested, bool, S_IRUGO);

/* Default is SYSTEM mode, 1 for host-guest mode */
int __read_mostly pt_mode = PT_MODE_SYSTEM;
module_param(pt_mode, int, S_IRUGO);

static DEFINE_STATIC_KEY_FALSE(vmx_l1d_should_flush);
static DEFINE_STATIC_KEY_FALSE(vmx_l1d_flush_cond);
static DEFINE_MUTEX(vmx_l1d_flush_mutex);

/* Storage for pre module init parameter parsing */
static enum vmx_l1d_flush_state __read_mostly vmentry_l1d_flush_param = VMENTER_L1D_FLUSH_AUTO;

static const struct {
	const char *option;
	bool for_parse;
} vmentry_l1d_param[] = {
	[VMENTER_L1D_FLUSH_AUTO]	 = {"auto", true},
	[VMENTER_L1D_FLUSH_NEVER]	 = {"never", true},
	[VMENTER_L1D_FLUSH_COND]	 = {"cond", true},
	[VMENTER_L1D_FLUSH_ALWAYS]	 = {"always", true},
	[VMENTER_L1D_FLUSH_EPT_DISABLED] = {"EPT disabled", false},
	[VMENTER_L1D_FLUSH_NOT_REQUIRED] = {"not required", false},
};

#define L1D_CACHE_ORDER 4
static void *vmx_l1d_flush_pages;

/* Control for disabling CPU Fill buffer clear */
static bool __read_mostly vmx_fb_clear_ctrl_available;

static int vmx_setup_l1d_flush(enum vmx_l1d_flush_state l1tf)
{
	struct page *page;
	unsigned int i;

	if (!boot_cpu_has_bug(X86_BUG_L1TF)) {
		l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_NOT_REQUIRED;
		return 0;
	}

	if (!enable_ept) {
		l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_EPT_DISABLED;
		return 0;
	}

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES)) {
		u64 msr;

		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, msr);
		if (msr & ARCH_CAP_SKIP_VMENTRY_L1DFLUSH) {
			l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_NOT_REQUIRED;
			return 0;
		}
	}

	/* If set to auto use the default l1tf mitigation method */
	if (l1tf == VMENTER_L1D_FLUSH_AUTO) {
		switch (l1tf_mitigation) {
		case L1TF_MITIGATION_OFF:
			l1tf = VMENTER_L1D_FLUSH_NEVER;
			break;
		case L1TF_MITIGATION_FLUSH_NOWARN:
		case L1TF_MITIGATION_FLUSH:
		case L1TF_MITIGATION_FLUSH_NOSMT:
			l1tf = VMENTER_L1D_FLUSH_COND;
			break;
		case L1TF_MITIGATION_FULL:
		case L1TF_MITIGATION_FULL_FORCE:
			l1tf = VMENTER_L1D_FLUSH_ALWAYS;
			break;
		}
	} else if (l1tf_mitigation == L1TF_MITIGATION_FULL_FORCE) {
		l1tf = VMENTER_L1D_FLUSH_ALWAYS;
	}

	if (l1tf != VMENTER_L1D_FLUSH_NEVER && !vmx_l1d_flush_pages &&
	    !boot_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		/*
		 * This allocation for vmx_l1d_flush_pages is not tied to a VM
		 * lifetime and so should not be charged to a memcg.
		 */
		page = alloc_pages(GFP_KERNEL, L1D_CACHE_ORDER);
		if (!page)
			return -ENOMEM;
		vmx_l1d_flush_pages = page_address(page);

		/*
		 * Initialize each page with a different pattern in
		 * order to protect against KSM in the nested
		 * virtualization case.
		 */
		for (i = 0; i < 1u << L1D_CACHE_ORDER; ++i) {
			memset(vmx_l1d_flush_pages + i * PAGE_SIZE, i + 1,
			       PAGE_SIZE);
		}
	}

	l1tf_vmx_mitigation = l1tf;

	if (l1tf != VMENTER_L1D_FLUSH_NEVER)
		static_branch_enable(&vmx_l1d_should_flush);
	else
		static_branch_disable(&vmx_l1d_should_flush);

	if (l1tf == VMENTER_L1D_FLUSH_COND)
		static_branch_enable(&vmx_l1d_flush_cond);
	else
		static_branch_disable(&vmx_l1d_flush_cond);
	return 0;
}

static int vmentry_l1d_flush_parse(const char *s)
{
	unsigned int i;

	if (s) {
		for (i = 0; i < ARRAY_SIZE(vmentry_l1d_param); i++) {
			if (vmentry_l1d_param[i].for_parse &&
			    sysfs_streq(s, vmentry_l1d_param[i].option))
				return i;
		}
	}
	return -EINVAL;
}

static int vmentry_l1d_flush_set(const char *s, const struct kernel_param *kp)
{
	int l1tf, ret;

	l1tf = vmentry_l1d_flush_parse(s);
	if (l1tf < 0)
		return l1tf;

	if (!boot_cpu_has(X86_BUG_L1TF))
		return 0;

	/*
	 * Has vmx_init() run already? If not then this is the pre init
	 * parameter parsing. In that case just store the value and let
	 * vmx_init() do the proper setup after enable_ept has been
	 * established.
	 */
	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_AUTO) {
		vmentry_l1d_flush_param = l1tf;
		return 0;
	}

	mutex_lock(&vmx_l1d_flush_mutex);
	ret = vmx_setup_l1d_flush(l1tf);
	mutex_unlock(&vmx_l1d_flush_mutex);
	return ret;
}

static int vmentry_l1d_flush_get(char *s, const struct kernel_param *kp)
{
	if (WARN_ON_ONCE(l1tf_vmx_mitigation >= ARRAY_SIZE(vmentry_l1d_param)))
		return sprintf(s, "???\n");

	return sprintf(s, "%s\n", vmentry_l1d_param[l1tf_vmx_mitigation].option);
}

static void vmx_setup_fb_clear_ctrl(void)
{
	u64 msr;

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES) &&
	    !boot_cpu_has_bug(X86_BUG_MDS) &&
	    !boot_cpu_has_bug(X86_BUG_TAA)) {
		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, msr);
		if (msr & ARCH_CAP_FB_CLEAR_CTRL)
			vmx_fb_clear_ctrl_available = true;
	}
}


static void vmx_update_fb_clear_dis(struct kvm_vcpu *vcpu, struct vcpu_tyche *vmx)
{
	vmx->disable_fb_clear = vmx_fb_clear_ctrl_available;

	/*
	 * If guest will not execute VERW, there is no need to set FB_CLEAR_DIS
	 * at VMEntry. Skip the MSR read/write when a guest has no use case to
	 * execute VERW.
	 */
	if ((vcpu->arch.arch_capabilities & ARCH_CAP_FB_CLEAR) ||
	   ((vcpu->arch.arch_capabilities & ARCH_CAP_MDS_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_TAA_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_PSDP_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_FBSDP_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_SBDR_SSDP_NO)))
		vmx->disable_fb_clear = false;
}

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
DEFINE_PER_CPU(struct vmcs *, current_vmcs);

/*
 * We maintain a per-CPU linked-list of VMCS loaded on that CPU. This is needed
 * when a CPU is brought down, and we need to VMCLEAR all VMCSs loaded on it.
 */
static DEFINE_PER_CPU(struct list_head, loaded_vmcss_on_cpu);

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);

struct vmcs_config vmcs_config;
struct vmx_capability vmx_capability;

static inline void tyche_segment_cache_clear(struct vcpu_tyche *tyche)
{
	tyche->segment_cache.bitmask = 0;
}

static int possible_passthrough_msr_slot(u32 msr)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(vmx_possible_passthrough_msrs); i++)
		if (vmx_possible_passthrough_msrs[i] == msr)
			return i;

	return -ENOENT;
}

static bool is_valid_passthrough_msr(u32 msr)
{
	bool r;

	switch (msr) {
	case 0x800 ... 0x8ff:
		/* x2APIC MSRs. These are handled in vmx_update_msr_bitmap_x2apic() */
		return true;
	case MSR_IA32_RTIT_STATUS:
	case MSR_IA32_RTIT_OUTPUT_BASE:
	case MSR_IA32_RTIT_OUTPUT_MASK:
	case MSR_IA32_RTIT_CR3_MATCH:
	case MSR_IA32_RTIT_ADDR0_A ... MSR_IA32_RTIT_ADDR3_B:
		/* PT MSRs. These are handled in pt_update_intercept_for_msr() */
	case MSR_LBR_SELECT:
	case MSR_LBR_TOS:
	case MSR_LBR_INFO_0 ... MSR_LBR_INFO_0 + 31:
	case MSR_LBR_NHM_FROM ... MSR_LBR_NHM_FROM + 31:
	case MSR_LBR_NHM_TO ... MSR_LBR_NHM_TO + 31:
	case MSR_LBR_CORE_FROM ... MSR_LBR_CORE_FROM + 8:
	case MSR_LBR_CORE_TO ... MSR_LBR_CORE_TO + 8:
		/* LBR MSRs. These are handled in vmx_update_intercept_for_lbr_msrs() */
		return true;
	}

	r = possible_passthrough_msr_slot(msr) != -ENOENT;

	WARN(!r, "Invalid MSR %x, please adapt vmx_possible_passthrough_msrs[]", msr);

	return r;
}

struct tyche_uret_msr *tyche_find_uret_msr(struct vcpu_tyche *vmx, u32 msr)
{
	int i;

	i = kvm_find_user_return_msr(msr);
	if (i >= 0)
		return &vmx->guest_uret_msrs[i];
	return NULL;
}

static int tyche_set_guest_uret_msr(struct vcpu_tyche *vmx,
				  struct tyche_uret_msr *msr, u64 data)
{
	unsigned int slot = msr - vmx->guest_uret_msrs;
	int ret = 0;

	if (msr->load_into_hardware) {
		preempt_disable();
		ret = kvm_set_user_return_msr(slot, data, msr->mask);
		preempt_enable();
	}
	if (!ret)
		msr->data = data;
	return ret;
}

static void __loaded_vmcs_clear(void *arg)
{
	struct loaded_vmcs *loaded_vmcs = arg;
	int cpu = raw_smp_processor_id();

	if (loaded_vmcs->cpu != cpu)
		return; /* vcpu migration can race with cpu offline */
	if (per_cpu(current_vmcs, cpu) == loaded_vmcs->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;

	tyche_vmcs_clear(loaded_vmcs->vmcs);
	if (loaded_vmcs->shadow_vmcs && loaded_vmcs->launched)
		tyche_vmcs_clear(loaded_vmcs->shadow_vmcs);

	list_del(&loaded_vmcs->loaded_vmcss_on_cpu_link);

	/*
	 * Ensure all writes to loaded_vmcs, including deleting it from its
	 * current percpu list, complete before setting loaded_vmcs->cpu to
	 * -1, otherwise a different cpu can see loaded_vmcs->cpu == -1 first
	 * and add loaded_vmcs to its percpu list before it's deleted from this
	 * cpu's list. Pairs with the smp_rmb() in vmx_vcpu_load_vmcs().
	 */
	smp_wmb();

	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;
}

void loaded_vmcs_clear(struct loaded_vmcs *loaded_vmcs)
{
	int cpu = loaded_vmcs->cpu;

	if (cpu != -1)
		smp_call_function_single(cpu, __loaded_vmcs_clear, loaded_vmcs,
					 1);
}

void tyche_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
	     (1u << DB_VECTOR) | (1u << AC_VECTOR);
	/*
	 * Guest access to VMware backdoor ports could legitimately
	 * trigger #GP because of TSS I/O permission bitmap.
	 * We intercept those #GP and allow access to them anyway
	 * as VMware does.
	 */
	if (enable_vmware_backdoor)
		eb |= (1u << GP_VECTOR);
	if ((vcpu->guest_debug &
	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		eb |= 1u << BP_VECTOR;
	if (to_tyche(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (!vmx_need_pf_intercept(vcpu))
		eb &= ~(1u << PF_VECTOR);

	/* When we are running a nested L2 guest and L1 specified for it a
	 * certain exception bitmap, we must trap the same exceptions and pass
	 * them to L1. When running L2, we will only handle the exceptions
	 * specified above if L1 did not want them.
	 */
	if (is_guest_mode(vcpu))
		eb |= get_vmcs12(vcpu)->exception_bitmap;
        else {
		int mask = 0, match = 0;

		if (enable_ept && (eb & (1u << PF_VECTOR))) {
			/*
			 * If EPT is enabled, #PF is currently only intercepted
			 * if MAXPHYADDR is smaller on the guest than on the
			 * host.  In that case we only care about present,
			 * non-reserved faults.  For vmcs02, however, PFEC_MASK
			 * and PFEC_MATCH are set in prepare_vmcs02_rare.
			 */
			mask = PFERR_PRESENT_MASK | PFERR_RSVD_MASK;
			match = PFERR_PRESENT_MASK;
		}
		tyche_vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, mask);
		tyche_vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, match);
	}

	/*
	 * Disabling xfd interception indicates that dynamic xfeatures
	 * might be used in the guest. Always trap #NM in this case
	 * to save guest xfd_err timely.
	 */
	if (vcpu->arch.xfd_no_write_intercept)
		eb |= (1u << NM_VECTOR);

	tyche_vmcs_write32(EXCEPTION_BITMAP, eb);
}

static u64 tyche_read_guest_kernel_gs_base(struct vcpu_tyche *vmx)
{
	preempt_disable();
	if (vmx->guest_state_loaded)
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
	preempt_enable();
	return vmx->msr_guest_kernel_gs_base;
}

static void tyche_write_guest_kernel_gs_base(struct vcpu_tyche *vmx, u64 data)
{
	preempt_disable();
	if (vmx->guest_state_loaded)
		wrmsrl(MSR_KERNEL_GS_BASE, data);
	preempt_enable();
	vmx->msr_guest_kernel_gs_base = data;
}

void tyche_vcpu_load_vmcs(struct kvm_vcpu *vcpu, int cpu,
			  struct loaded_vmcs *buddy)
{
	struct vcpu_tyche *vmx = to_tyche(vcpu);
	bool already_loaded = vmx->loaded_vmcs->cpu == cpu;
	struct vmcs *prev;

	if (!already_loaded) {
		loaded_vmcs_clear(vmx->loaded_vmcs);
		local_irq_disable();

		/*
		 * Ensure loaded_vmcs->cpu is read before adding loaded_vmcs to
		 * this cpu's percpu list, otherwise it may not yet be deleted
		 * from its previous cpu's percpu list.  Pairs with the
		 * smb_wmb() in __loaded_vmcs_clear().
		 */
		smp_rmb();

		list_add(&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link,
			 &per_cpu(loaded_vmcss_on_cpu, cpu));
		local_irq_enable();
	}

	prev = per_cpu(current_vmcs, cpu);
	if (prev != vmx->loaded_vmcs->vmcs) {
		per_cpu(current_vmcs, cpu) = vmx->loaded_vmcs->vmcs;
		tyche_vmcs_load(vmx->loaded_vmcs->vmcs);

		/*
		 * No indirect branch prediction barrier needed when switching
		 * the active VMCS within a vCPU, unless IBRS is advertised to
		 * the vCPU.  To minimize the number of IBPBs executed, KVM
		 * performs IBPB on nested VM-Exit (a single nested transition
		 * may switch the active VMCS multiple times).
		 */
		if (!buddy || WARN_ON_ONCE(buddy->vmcs != prev))
			indirect_branch_prediction_barrier();
	}

	if (!already_loaded) {
		void *gdt = get_current_gdt_ro();

		/*
		 * Flush all EPTP/VPID contexts, the new pCPU may have stale
		 * TLB entries from its previous association with the vCPU.
		 */
		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

		/*
		 * Linux uses per-cpu TSS and GDT, so set these when switching
		 * processors.  See 22.2.4.
		 */
		tyche_vmcs_writel(
			HOST_TR_BASE,
			(unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
		tyche_vmcs_writel(HOST_GDTR_BASE,
				  (unsigned long)gdt); /* 22.2.4 */

		if (IS_ENABLED(CONFIG_IA32_EMULATION) ||
		    IS_ENABLED(CONFIG_X86_32)) {
			/* 22.2.3 */
			tyche_vmcs_writel(
				HOST_IA32_SYSENTER_ESP,
				(unsigned long)(cpu_entry_stack(cpu) + 1));
		}

		vmx->loaded_vmcs->cpu = cpu;
	}
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void tyche_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tyche *vmx = to_tyche(vcpu);

	tyche_vcpu_load_vmcs(vcpu, cpu, NULL);

	// FIXME: we probably don't want posted interrupt for a basic VM
	// vmx_vcpu_pi_load(vcpu, cpu);

	vmx->host_debugctlmsr = get_debugctlmsr();
}

/*
 * nested_vmx_allowed() checks whether a guest should be allowed to use VMX
 * instructions and MSRs (i.e., nested VMX). Nested VMX is disabled for
 * all guests if the "nested" module option is off, and can also be disabled
 * for a single guest by disabling its VMX cpuid bit.
 */
bool nested_vmx_allowed(struct kvm_vcpu *vcpu)
{
	return nested && guest_cpuid_has(vcpu, X86_FEATURE_VMX);
}

#define KVM_SUPPORTED_FEATURE_CONTROL  (FEAT_CTL_LOCKED			 | \
					FEAT_CTL_VMX_ENABLED_INSIDE_SMX	 | \
					FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX | \
					FEAT_CTL_SGX_LC_ENABLED		 | \
					FEAT_CTL_SGX_ENABLED		 | \
					FEAT_CTL_LMCE_ENABLED)

static inline bool is_vmx_feature_control_msr_valid(struct vcpu_tyche *vmx,
						    struct msr_data *msr)
{
	uint64_t valid_bits;

	/*
	 * Ensure KVM_SUPPORTED_FEATURE_CONTROL is updated when new bits are
	 * exposed to the guest.
	 */
	WARN_ON_ONCE(vmx->msr_ia32_feature_control_valid_bits &
		     ~KVM_SUPPORTED_FEATURE_CONTROL);

	if (!msr->host_initiated &&
	    (vmx->msr_ia32_feature_control & FEAT_CTL_LOCKED))
		return false;

	if (msr->host_initiated)
		valid_bits = KVM_SUPPORTED_FEATURE_CONTROL;
	else
		valid_bits = vmx->msr_ia32_feature_control_valid_bits;

	return !(msr->data & ~valid_bits);
}

static int tyche_get_msr_feature(struct kvm_msr_entry *msr)
{
	switch (msr->index) {
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!nested)
			return 1;
		return tyche_get_vmx_msr(&vmcs_config.nested, msr->index,
					 &msr->data);
	default:
		return KVM_MSR_RET_INVALID;
	}
}

/*
 * Reads an msr value (of 'msr_info->index') into 'msr_info->data'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int tyche_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_tyche *vmx = to_tyche(vcpu);
	struct tyche_uret_msr *msr;
	u32 index;

	switch (msr_info->index) {
	case MSR_FS_BASE:
		msr_info->data = tyche_vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		msr_info->data = tyche_vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		msr_info->data = tyche_read_guest_kernel_gs_base(vmx);
		break;
	case MSR_EFER:
		return kvm_get_msr_common(vcpu, msr_info);
	case MSR_IA32_TSX_CTRL:
		if (!msr_info->host_initiated &&
		    !(vcpu->arch.arch_capabilities & ARCH_CAP_TSX_CTRL_MSR))
			return 1;
		goto find_uret_msr;
	case MSR_IA32_UMWAIT_CONTROL:
		if (!msr_info->host_initiated && !vmx_has_waitpkg(vmx))
			return 1;

		msr_info->data = vmx->msr_ia32_umwait_control;
		break;
	case MSR_IA32_SPEC_CTRL:
		if (!msr_info->host_initiated && !guest_has_spec_ctrl_msr(vcpu))
			return 1;

		msr_info->data = to_tyche(vcpu)->spec_ctrl;
		break;
	case MSR_IA32_SYSENTER_CS:
		msr_info->data = tyche_vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = tyche_vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = tyche_vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported() ||
		    (!msr_info->host_initiated &&
		     !guest_cpuid_has(vcpu, X86_FEATURE_MPX)))
			return 1;
		msr_info->data = tyche_vmcs_read64(GUEST_BNDCFGS);
		break;
	case MSR_IA32_MCG_EXT_CTL:
		if (!msr_info->host_initiated &&
		    !(vmx->msr_ia32_feature_control & FEAT_CTL_LMCE_ENABLED))
			return 1;
		msr_info->data = vcpu->arch.mcg_ext_ctl;
		break;
	case MSR_IA32_FEAT_CTL:
		msr_info->data = vmx->msr_ia32_feature_control;
		break;
	case MSR_IA32_SGXLEPUBKEYHASH0 ... MSR_IA32_SGXLEPUBKEYHASH3:
		if (!msr_info->host_initiated &&
		    !guest_cpuid_has(vcpu, X86_FEATURE_SGX_LC))
			return 1;
		msr_info->data =
			to_tyche(vcpu)->msr_ia32_sgxlepubkeyhash
				[msr_info->index - MSR_IA32_SGXLEPUBKEYHASH0];
		break;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!nested_vmx_allowed(vcpu))
			return 1;
#if 0 // FIXME
		if (tyche_get_vmx_msr(&vmx->nested.msrs, msr_info->index,
				    &msr_info->data))
			return 1;
		/*
		 * Enlightened VMCS v1 doesn't have certain VMCS fields but
		 * instead of just ignoring the features, different Hyper-V
		 * versions are either trying to use them and fail or do some
		 * sanity checking and refuse to boot. Filter all unsupported
		 * features out.
		 */
		if (!msr_info->host_initiated && guest_cpuid_has_evmcs(vcpu))
			nested_evmcs_filter_control_msr(vcpu, msr_info->index,
							&msr_info->data);
#endif
		break;
	case MSR_IA32_RTIT_CTL:
		if (!vmx_pt_mode_is_host_guest())
			return 1;
		msr_info->data = vmx->pt_desc.guest.ctl;
		break;
	case MSR_IA32_RTIT_STATUS:
		if (!vmx_pt_mode_is_host_guest())
			return 1;
		msr_info->data = vmx->pt_desc.guest.status;
		break;
	case MSR_IA32_RTIT_CR3_MATCH:
		if (!vmx_pt_mode_is_host_guest() ||
		    !intel_pt_validate_cap(vmx->pt_desc.caps,
					   PT_CAP_cr3_filtering))
			return 1;
		msr_info->data = vmx->pt_desc.guest.cr3_match;
		break;
	case MSR_IA32_RTIT_OUTPUT_BASE:
		if (!vmx_pt_mode_is_host_guest() ||
		    (!intel_pt_validate_cap(vmx->pt_desc.caps,
					    PT_CAP_topa_output) &&
		     !intel_pt_validate_cap(vmx->pt_desc.caps,
					    PT_CAP_single_range_output)))
			return 1;
		msr_info->data = vmx->pt_desc.guest.output_base;
		break;
	case MSR_IA32_RTIT_OUTPUT_MASK:
		if (!vmx_pt_mode_is_host_guest() ||
		    (!intel_pt_validate_cap(vmx->pt_desc.caps,
					    PT_CAP_topa_output) &&
		     !intel_pt_validate_cap(vmx->pt_desc.caps,
					    PT_CAP_single_range_output)))
			return 1;
		msr_info->data = vmx->pt_desc.guest.output_mask;
		break;
	case MSR_IA32_RTIT_ADDR0_A ... MSR_IA32_RTIT_ADDR3_B:
		index = msr_info->index - MSR_IA32_RTIT_ADDR0_A;
		if (!vmx_pt_mode_is_host_guest() ||
		    (index >= 2 * vmx->pt_desc.num_address_ranges))
			return 1;
		if (index % 2)
			msr_info->data = vmx->pt_desc.guest.addr_b[index / 2];
		else
			msr_info->data = vmx->pt_desc.guest.addr_a[index / 2];
		break;
	case MSR_IA32_DEBUGCTLMSR:
		msr_info->data = tyche_vmcs_read64(GUEST_IA32_DEBUGCTL);
		break;
	default:
find_uret_msr:
		msr = tyche_find_uret_msr(vmx, msr_info->index);
		if (msr) {
			msr_info->data = msr->data;
			break;
		}
		return kvm_get_msr_common(vcpu, msr_info);
	}

	return 0;
}

static u64 nested_vmx_truncate_sysenter_addr(struct kvm_vcpu *vcpu,
						    u64 data)
{
#ifdef CONFIG_X86_64
	if (!guest_cpuid_has(vcpu, X86_FEATURE_LM))
		return (u32)data;
#endif
	return (unsigned long)data;
}

/*
 * Writes msr value into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_tyche *vmx = to_tyche(vcpu);
	struct tyche_uret_msr *msr;
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;
	u32 index;

	switch (msr_index) {
	case MSR_EFER:
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_FS_BASE:
		tyche_segment_cache_clear(vmx);
		tyche_vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		tyche_segment_cache_clear(vmx);
		tyche_vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		tyche_write_guest_kernel_gs_base(vmx, data);
		break;
	case MSR_IA32_XFD:
		ret = kvm_set_msr_common(vcpu, msr_info);
		/*
		 * Always intercepting WRMSR could incur non-negligible
		 * overhead given xfd might be changed frequently in
		 * guest context switch. Disable write interception
		 * upon the first write with a non-zero value (indicating
		 * potential usage on dynamic xfeatures). Also update
		 * exception bitmap to trap #NM for proper virtualization
		 * of guest xfd_err.
		 */
		if (!ret && data) {
			vmx_disable_intercept_for_msr(vcpu, MSR_IA32_XFD,
						      MSR_TYPE_RW);
			vcpu->arch.xfd_no_write_intercept = true;
			tyche_update_exception_bitmap(vcpu);
		}
		break;
	case MSR_IA32_SYSENTER_CS:
		if (is_guest_mode(vcpu))
			get_vmcs12(vcpu)->guest_sysenter_cs = data;
		tyche_vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		if (is_guest_mode(vcpu)) {
			data = nested_vmx_truncate_sysenter_addr(vcpu, data);
			get_vmcs12(vcpu)->guest_sysenter_eip = data;
		}
		tyche_vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		if (is_guest_mode(vcpu)) {
			data = nested_vmx_truncate_sysenter_addr(vcpu, data);
			get_vmcs12(vcpu)->guest_sysenter_esp = data;
		}
		tyche_vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_DEBUGCTLMSR: {
#if 0 // FIXME: I don't think this part is necessary to boot up a minimal VM
		u64 invalid;

		invalid = data & ~vmx_get_supported_debugctl(
					 vcpu, msr_info->host_initiated);
		if (invalid & (DEBUGCTLMSR_BTF | DEBUGCTLMSR_LBR)) {
			if (report_ignored_msrs)
				vcpu_unimpl(
					vcpu,
					"%s: BTF|LBR in IA32_DEBUGCTLMSR 0x%llx, nop\n",
					__func__, data);
			data &= ~(DEBUGCTLMSR_BTF | DEBUGCTLMSR_LBR);
			invalid &= ~(DEBUGCTLMSR_BTF | DEBUGCTLMSR_LBR);
		}

		if (invalid)
			return 1;

		if (is_guest_mode(vcpu) && get_vmcs12(vcpu)->vm_exit_controls &
						   VM_EXIT_SAVE_DEBUG_CONTROLS)
			get_vmcs12(vcpu)->guest_ia32_debugctl = data;

		tyche_vmcs_write64(GUEST_IA32_DEBUGCTL, data);
		if (intel_pmu_lbr_is_enabled(vcpu) &&
		    !to_tyche(vcpu)->lbr_desc.event && (data & DEBUGCTLMSR_LBR))
			intel_pmu_create_guest_lbr_event(vcpu);
#endif
		printk(KERN_ERR "MSR_IA32_DEBUGCTLMSR not implemented\n");
		return 0;
	}
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported() ||
		    (!msr_info->host_initiated &&
		     !guest_cpuid_has(vcpu, X86_FEATURE_MPX)))
			return 1;
		if (is_noncanonical_address(data & PAGE_MASK, vcpu) ||
		    (data & MSR_IA32_BNDCFGS_RSVD))
			return 1;

		if (is_guest_mode(vcpu) &&
		    ((vmx->nested.msrs.entry_ctls_high &
		      VM_ENTRY_LOAD_BNDCFGS) ||
		     (vmx->nested.msrs.exit_ctls_high & VM_EXIT_CLEAR_BNDCFGS)))
			get_vmcs12(vcpu)->guest_bndcfgs = data;

		tyche_vmcs_write64(GUEST_BNDCFGS, data);
		break;
	case MSR_IA32_UMWAIT_CONTROL:
		if (!msr_info->host_initiated && !vmx_has_waitpkg(vmx))
			return 1;

		/* The reserved bit 1 and non-32 bit [63:32] should be zero */
		if (data & (BIT_ULL(1) | GENMASK_ULL(63, 32)))
			return 1;

		vmx->msr_ia32_umwait_control = data;
		break;
	case MSR_IA32_SPEC_CTRL:
#if 0
		if (!msr_info->host_initiated && !guest_has_spec_ctrl_msr(vcpu))
			return 1;

		if (kvm_spec_ctrl_test_value(data))
			return 1;

		vmx->spec_ctrl = data;
		if (!data)
			break;

		/*
		 * For non-nested:
		 * When it's written (to non-zero) for the first time, pass
		 * it through.
		 *
		 * For nested:
		 * The handling of the MSR bitmap for L2 guests is done in
		 * nested_vmx_prepare_msr_bitmap. We should not touch the
		 * vmcs02.msr_bitmap here since it gets completely overwritten
		 * in the merging. We update the vmcs01 here for L1 as well
		 * since it will end up touching the MSR anyway now.
		 */
		vmx_disable_intercept_for_msr(vcpu, MSR_IA32_SPEC_CTRL,
					      MSR_TYPE_RW);
		break;
#endif
		printk(KERN_ERR "MSR_IA32_SPEC_CTRL not implemented\n");
		break;
	case MSR_IA32_TSX_CTRL:
		if (!msr_info->host_initiated &&
		    !(vcpu->arch.arch_capabilities & ARCH_CAP_TSX_CTRL_MSR))
			return 1;
		if (data & ~(TSX_CTRL_RTM_DISABLE | TSX_CTRL_CPUID_CLEAR))
			return 1;
		goto find_uret_msr;
	case MSR_IA32_PRED_CMD:
#if 0 // FIXME
		if (!msr_info->host_initiated && !guest_has_pred_cmd_msr(vcpu))
			return 1;

		if (data & ~PRED_CMD_IBPB)
			return 1;
		if (!boot_cpu_has(X86_FEATURE_IBPB))
			return 1;
		if (!data)
			break;

		wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);

		/*
		 * For non-nested:
		 * When it's written (to non-zero) for the first time, pass
		 * it through.
		 *
		 * For nested:
		 * The handling of the MSR bitmap for L2 guests is done in
		 * nested_vmx_prepare_msr_bitmap. We should not touch the
		 * vmcs02.msr_bitmap here since it gets completely overwritten
		 * in the merging.
		 */
		vmx_disable_intercept_for_msr(vcpu, MSR_IA32_PRED_CMD,
					      MSR_TYPE_W);
		break;
#endif
		printk(KERN_ERR "MSR_IA32_PRED_CMD not implemented\n");
	case MSR_IA32_CR_PAT:
		if (!kvm_pat_valid(data))
			return 1;

		if (is_guest_mode(vcpu) &&
		    get_vmcs12(vcpu)->vm_exit_controls & VM_EXIT_SAVE_IA32_PAT)
			get_vmcs12(vcpu)->guest_ia32_pat = data;

		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			tyche_vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_IA32_MCG_EXT_CTL:
		if ((!msr_info->host_initiated &&
		     !(to_tyche(vcpu)->msr_ia32_feature_control &
		       FEAT_CTL_LMCE_ENABLED)) ||
		    (data & ~MCG_EXT_CTL_LMCE_EN))
			return 1;
		vcpu->arch.mcg_ext_ctl = data;
		break;
	case MSR_IA32_FEAT_CTL:
#if 0
		if (!is_vmx_feature_control_msr_valid(vmx, msr_info))
			return 1;

		vmx->msr_ia32_feature_control = data;
		if (msr_info->host_initiated && data == 0)
			vmx_leave_nested(vcpu);

		/* SGX may be enabled/disabled by guest's firmware */
		tyche_write_encls_bitmap(vcpu, NULL);
		break;
#endif
		printk(KERN_ERR "MSR_IA32_FEAT_CTL not implemented\n");
		break;
	case MSR_IA32_SGXLEPUBKEYHASH0 ... MSR_IA32_SGXLEPUBKEYHASH3:
		/*
		 * On real hardware, the LE hash MSRs are writable before
		 * the firmware sets bit 0 in MSR 0x7a ("activating" SGX),
		 * at which point SGX related bits in IA32_FEATURE_CONTROL
		 * become writable.
		 *
		 * KVM does not emulate SGX activation for simplicity, so
		 * allow writes to the LE hash MSRs if IA32_FEATURE_CONTROL
		 * is unlocked.  This is technically not architectural
		 * behavior, but it's close enough.
		 */
		if (!msr_info->host_initiated &&
		    (!guest_cpuid_has(vcpu, X86_FEATURE_SGX_LC) ||
		     ((vmx->msr_ia32_feature_control & FEAT_CTL_LOCKED) &&
		      !(vmx->msr_ia32_feature_control &
			FEAT_CTL_SGX_LC_ENABLED))))
			return 1;
		vmx->msr_ia32_sgxlepubkeyhash[msr_index -
					      MSR_IA32_SGXLEPUBKEYHASH0] = data;
		break;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!msr_info->host_initiated)
			return 1; /* they are read-only */
		if (!nested_vmx_allowed(vcpu))
			return 1;
		return tyche_set_vmx_msr(vcpu, msr_index, data);
	case MSR_IA32_RTIT_CTL:
#if 0 // FIXME: don't think this is necessary...
		if (!vmx_pt_mode_is_host_guest() ||
		    vmx_rtit_ctl_check(vcpu, data) || vmx->nested.vmxon)
			return 1;
		tyche_vmcs_write64(GUEST_IA32_RTIT_CTL, data);
		vmx->pt_desc.guest.ctl = data;
		pt_update_intercept_for_msr(vcpu);
		break;
#endif
		printk(KERN_ERR "MSR_IA32_RTIT_CTL not implemented\n");
		return 0;
	case MSR_IA32_RTIT_STATUS:
#if 0 // FIXME: don't think this is necessary...
		if (!pt_can_write_msr(vmx))
			return 1;
		if (data & MSR_IA32_RTIT_STATUS_MASK)
			return 1;
		vmx->pt_desc.guest.status = data;
		break;
#endif
		printk(KERN_ERR "MSR_IA32_RTIT_STATUS not implemented\n");
		break;
	case MSR_IA32_RTIT_CR3_MATCH:
#if 0 // FIXME: don't think this is necessary...
		if (!pt_can_write_msr(vmx))
			return 1;
		if (!intel_pt_validate_cap(vmx->pt_desc.caps,
					   PT_CAP_cr3_filtering))
			return 1;
		vmx->pt_desc.guest.cr3_match = data;
		break;
#endif
		printk(KERN_ERR "MSR_IA32_RTIT_CR3_MATCH not implemented\n");
		break;
	case MSR_IA32_RTIT_OUTPUT_BASE:
#if 0 // FIXME: don't think this is necessary...
		if (!pt_can_write_msr(vmx))
			return 1;
		if (!intel_pt_validate_cap(vmx->pt_desc.caps,
					   PT_CAP_topa_output) &&
		    !intel_pt_validate_cap(vmx->pt_desc.caps,
					   PT_CAP_single_range_output))
			return 1;
		if (!pt_output_base_valid(vcpu, data))
			return 1;
		vmx->pt_desc.guest.output_base = data;
		break;
#endif
		printk(KERN_ERR "MSR_IA32_RTIT_OUTPUT_BASE not implemented\n");
		break;
	case MSR_IA32_RTIT_OUTPUT_MASK:
#if 0 // FIXME: don't think this is necessary...
		if (!pt_can_write_msr(vmx))
			return 1;
		if (!intel_pt_validate_cap(vmx->pt_desc.caps,
					   PT_CAP_topa_output) &&
		    !intel_pt_validate_cap(vmx->pt_desc.caps,
					   PT_CAP_single_range_output))
			return 1;
		vmx->pt_desc.guest.output_mask = data;
		break;
#endif
		printk(KERN_ERR "MSR_IA32_RTIT_OUTPUT_MASK not implemented\n");
		break;
	case MSR_IA32_RTIT_ADDR0_A ... MSR_IA32_RTIT_ADDR3_B:
#if 0 // FIXME: don't think this is necessary...
		if (!pt_can_write_msr(vmx))
			return 1;
		index = msr_info->index - MSR_IA32_RTIT_ADDR0_A;
		if (index >= 2 * vmx->pt_desc.num_address_ranges)
			return 1;
		if (is_noncanonical_address(data, vcpu))
			return 1;
		if (index % 2)
			vmx->pt_desc.guest.addr_b[index / 2] = data;
		else
			vmx->pt_desc.guest.addr_a[index / 2] = data;
		break;
#endif
		printk(KERN_ERR "MSR_IA32_RTIT_ADDR0_A ... MSR_IA32_RTIT_ADDR3_B not implemented\n");
		break;
	case MSR_IA32_PERF_CAPABILITIES:
#if 0 // FIXME: don't think this is necessary...
		if (data && !vcpu_to_pmu(vcpu)->version)
			return 1;
		if (data & PMU_CAP_LBR_FMT) {
			if ((data & PMU_CAP_LBR_FMT) !=
			    (kvm_caps.supported_perf_cap & PMU_CAP_LBR_FMT))
				return 1;
			if (!cpuid_model_is_consistent(vcpu))
				return 1;
		}
		if (data & PERF_CAP_PEBS_FORMAT) {
			if ((data & PERF_CAP_PEBS_MASK) !=
			    (kvm_caps.supported_perf_cap & PERF_CAP_PEBS_MASK))
				return 1;
			if (!guest_cpuid_has(vcpu, X86_FEATURE_DS))
				return 1;
			if (!guest_cpuid_has(vcpu, X86_FEATURE_DTES64))
				return 1;
			if (!cpuid_model_is_consistent(vcpu))
				return 1;
		}
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
#endif
		printk(KERN_ERR "MSR_IA32_PERF_CAPABILITIES not implemented\n");
		break;

	default:
find_uret_msr:
		msr = tyche_find_uret_msr(vmx, msr_index);
		if (msr)
			ret = tyche_set_guest_uret_msr(vmx, msr, data);
		else
			ret = kvm_set_msr_common(vcpu, msr_info);
	}

	/* FB_CLEAR may have changed, also update the FB_CLEAR_DIS behavior */
	if (msr_index == MSR_IA32_ARCH_CAPABILITIES)
		vmx_update_fb_clear_dis(vcpu, vmx);

	return ret;
}

static bool tyche_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	/*
	 * We operate under the default treatment of SMM, so VMX cannot be
	 * enabled under SMM.  Note, whether or not VMXE is allowed at all,
	 * i.e. is a reserved bit, is handled by common x86 code.
	 */
	if ((cr4 & X86_CR4_VMXE) && is_smm(vcpu))
		return false;

#if 0 // FIXME: skip nested for now
	if (to_tyche(vcpu)->nested.vmxon && !nested_cr4_valid(vcpu, cr4))
		return false;
#endif

	return true;
}

void tyche_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old_cr4 = vcpu->arch.cr4;
	struct vcpu_tyche *vmx = to_tyche(vcpu);
	/*
	 * Pass through host's Machine Check Enable value to hw_cr4, which
	 * is in force while we are in guest mode.  Do not let guests control
	 * this bit, even if host CR4.MCE == 0.
	 */
	unsigned long hw_cr4;

	hw_cr4 = (cr4_read_shadow() & X86_CR4_MCE) | (cr4 & ~X86_CR4_MCE);
	if (enable_unrestricted_guest)
		hw_cr4 |= KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST;
	else if (vmx->rmode.vm86_active)
		hw_cr4 |= KVM_RMODE_VM_CR4_ALWAYS_ON;
	else
		hw_cr4 |= KVM_PMODE_VM_CR4_ALWAYS_ON;

	if (!boot_cpu_has(X86_FEATURE_UMIP) && vmx_umip_emulated()) {
		if (cr4 & X86_CR4_UMIP) {
			secondary_exec_controls_setbit(vmx,
						       SECONDARY_EXEC_DESC);
			hw_cr4 &= ~X86_CR4_UMIP;
		}
#if 0 // FIXME: skip nested for now
		else if (!is_guest_mode(vcpu) ||
			!nested_cpu_has2(get_vmcs12(vcpu), SECONDARY_EXEC_DESC)) {
			secondary_exec_controls_clearbit(vmx, SECONDARY_EXEC_DESC);
		}
#endif
	}

	vcpu->arch.cr4 = cr4;
	kvm_register_mark_available(vcpu, VCPU_EXREG_CR4);

	if (!enable_unrestricted_guest) {
		if (enable_ept) {
			if (!is_paging(vcpu)) {
				hw_cr4 &= ~X86_CR4_PAE;
				hw_cr4 |= X86_CR4_PSE;
			} else if (!(cr4 & X86_CR4_PAE)) {
				hw_cr4 &= ~X86_CR4_PAE;
			}
		}

		/*
		 * SMEP/SMAP/PKU is disabled if CPU is in non-paging mode in
		 * hardware.  To emulate this behavior, SMEP/SMAP/PKU needs
		 * to be manually disabled when guest switches to non-paging
		 * mode.
		 *
		 * If !enable_unrestricted_guest, the CPU is always running
		 * with CR0.PG=1 and CR4 needs to be modified.
		 * If enable_unrestricted_guest, the CPU automatically
		 * disables SMEP/SMAP/PKU when the guest sets CR0.PG=0.
		 */
		if (!is_paging(vcpu))
			hw_cr4 &= ~(X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE);
	}

	tyche_vmcs_writel(CR4_READ_SHADOW, cr4);
	tyche_vmcs_writel(GUEST_CR4, hw_cr4);

	if ((cr4 ^ old_cr4) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		kvm_update_cpuid_runtime(vcpu);
}

static void tyche_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = tyche_vmcs_read32(GUEST_IDTR_LIMIT);
	dt->address = tyche_vmcs_readl(GUEST_IDTR_BASE);
}

static void tyche_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	tyche_vmcs_write32(GUEST_IDTR_LIMIT, dt->size);
	tyche_vmcs_writel(GUEST_IDTR_BASE, dt->address);
}

static void tyche_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = tyche_vmcs_read32(GUEST_GDTR_LIMIT);
	dt->address = tyche_vmcs_readl(GUEST_GDTR_BASE);
}

static void tyche_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	tyche_vmcs_write32(GUEST_GDTR_LIMIT, dt->size);
	tyche_vmcs_writel(GUEST_GDTR_BASE, dt->address);
}

static void vmx_msr_bitmap_l01_changed(struct vcpu_tyche *vmx)
{
	vmx->nested.force_msr_bitmap_recalc = true;
}

void vmx_disable_intercept_for_msr(struct kvm_vcpu *vcpu, u32 msr, int type)
{
	struct vcpu_tyche *vmx = to_tyche(vcpu);
	unsigned long *msr_bitmap = vmx->vmcs01.msr_bitmap;

	if (!cpu_has_vmx_msr_bitmap())
		return;

	vmx_msr_bitmap_l01_changed(vmx);

	/*
	 * Mark the desired intercept state in shadow bitmap, this is needed
	 * for resync when the MSR filters change.
	*/
	if (is_valid_passthrough_msr(msr)) {
		int idx = possible_passthrough_msr_slot(msr);

		if (idx != -ENOENT) {
			if (type & MSR_TYPE_R)
				clear_bit(idx, vmx->shadow_msr_intercept.read);
			if (type & MSR_TYPE_W)
				clear_bit(idx, vmx->shadow_msr_intercept.write);
		}
	}

	if ((type & MSR_TYPE_R) &&
	    !kvm_msr_allowed(vcpu, msr, KVM_MSR_FILTER_READ)) {
		vmx_set_msr_bitmap_read(msr_bitmap, msr);
		type &= ~MSR_TYPE_R;
	}

	if ((type & MSR_TYPE_W) &&
	    !kvm_msr_allowed(vcpu, msr, KVM_MSR_FILTER_WRITE)) {
		vmx_set_msr_bitmap_write(msr_bitmap, msr);
		type &= ~MSR_TYPE_W;
	}

	if (type & MSR_TYPE_R)
		vmx_clear_msr_bitmap_read(msr_bitmap, msr);

	if (type & MSR_TYPE_W)
		vmx_clear_msr_bitmap_write(msr_bitmap, msr);
}

static void tyche_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	tyche_vmcs_writel(GUEST_DR7, val);
}

static struct kvm_x86_ops tyche_x86_ops __initdata = {
	.name = "tyche_intel",

	// .hardware_unsetup = vmx_hardware_unsetup,

	// .hardware_enable = vmx_hardware_enable,
	// .hardware_disable = vmx_hardware_disable,
	// .has_emulated_msr = vmx_has_emulated_msr,

	.vm_size = sizeof(struct kvm_tyche),
	// .vm_init = vmx_vm_init,
	// .vm_destroy = vmx_vm_destroy,

	// .vcpu_precreate = vmx_vcpu_precreate,
	// .vcpu_create = vmx_vcpu_create,
	// .vcpu_free = vmx_vcpu_free,
	// .vcpu_reset = vmx_vcpu_reset,

	// .prepare_switch_to_guest = vmx_prepare_switch_to_guest,
	.vcpu_load = tyche_vcpu_load,
	// .vcpu_put = vmx_vcpu_put,

	.update_exception_bitmap = tyche_update_exception_bitmap,
	.get_msr_feature = tyche_get_msr_feature,
	.get_msr = tyche_get_msr,
	// .set_msr = vmx_set_msr,
	// .get_segment_base = vmx_get_segment_base,
	// .get_segment = vmx_get_segment,
	// .set_segment = vmx_set_segment,
	// .get_cpl = vmx_get_cpl,
	// .get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	// .set_cr0 = vmx_set_cr0,
	// .is_valid_cr4 = vmx_is_valid_cr4,
	// .set_cr4 = vmx_set_cr4,
	// .set_efer = vmx_set_efer,
	.get_idt = tyche_get_idt,
	.set_idt = tyche_set_idt,
	.get_gdt = tyche_get_gdt,
	.set_gdt = tyche_set_gdt,
	.set_dr7 = tyche_set_dr7,
	// .sync_dirty_debug_regs = vmx_sync_dirty_debug_regs,
	// .cache_reg = vmx_cache_reg,
	// .get_rflags = vmx_get_rflags,
	// .set_rflags = vmx_set_rflags,
	// .get_if_flag = vmx_get_if_flag,

	// .flush_tlb_all = vmx_flush_tlb_all,
	// .flush_tlb_current = vmx_flush_tlb_current,
	// .flush_tlb_gva = vmx_flush_tlb_gva,
	// .flush_tlb_guest = vmx_flush_tlb_guest,

	// .vcpu_pre_run = vmx_vcpu_pre_run,
	// .vcpu_run = vmx_vcpu_run,
	// .handle_exit = vmx_handle_exit,
	// .skip_emulated_instruction = vmx_skip_emulated_instruction,
	// .update_emulated_instruction = vmx_update_emulated_instruction,
	// .set_interrupt_shadow = vmx_set_interrupt_shadow,
	// .get_interrupt_shadow = vmx_get_interrupt_shadow,
	// .patch_hypercall = vmx_patch_hypercall,
	// .inject_irq = vmx_inject_irq,
	// .inject_nmi = vmx_inject_nmi,
	// .inject_exception = vmx_inject_exception,
	// .cancel_injection = vmx_cancel_injection,
	// .interrupt_allowed = vmx_interrupt_allowed,
	// .nmi_allowed = vmx_nmi_allowed,
	// .get_nmi_mask = vmx_get_nmi_mask,
	// .set_nmi_mask = vmx_set_nmi_mask,
	// .enable_nmi_window = vmx_enable_nmi_window,
	// .enable_irq_window = vmx_enable_irq_window,
	// .update_cr8_intercept = vmx_update_cr8_intercept,
	// .set_virtual_apic_mode = vmx_set_virtual_apic_mode,
	// .set_apic_access_page_addr = vmx_set_apic_access_page_addr,
	// .refresh_apicv_exec_ctrl = vmx_refresh_apicv_exec_ctrl,
	// .load_eoi_exitmap = vmx_load_eoi_exitmap,
	// .apicv_post_state_restore = vmx_apicv_post_state_restore,
	// .check_apicv_inhibit_reasons = vmx_check_apicv_inhibit_reasons,
	// .hwapic_irr_update = vmx_hwapic_irr_update,
	// .hwapic_isr_update = vmx_hwapic_isr_update,
	// .guest_apic_has_interrupt = vmx_guest_apic_has_interrupt,
	// .sync_pir_to_irr = vmx_sync_pir_to_irr,
	// .deliver_interrupt = vmx_deliver_interrupt,
	// .dy_apicv_has_pending_interrupt = pi_has_pending_interrupt,

	// .set_tss_addr = vmx_set_tss_addr,
	// .set_identity_map_addr = vmx_set_identity_map_addr,
	// .get_mt_mask = vmx_get_mt_mask,

	// .get_exit_info = vmx_get_exit_info,

	// .vcpu_after_set_cpuid = vmx_vcpu_after_set_cpuid,

	// .has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	// .get_l2_tsc_offset = vmx_get_l2_tsc_offset,
	// .get_l2_tsc_multiplier = vmx_get_l2_tsc_multiplier,
	// .write_tsc_offset = vmx_write_tsc_offset,
	// .write_tsc_multiplier = vmx_write_tsc_multiplier,

	// .load_mmu_pgd = vmx_load_mmu_pgd,

	// .check_intercept = vmx_check_intercept,
	// .handle_exit_irqoff = vmx_handle_exit_irqoff,

	// .request_immediate_exit = vmx_request_immediate_exit,

	// .sched_in = vmx_sched_in,

	// .cpu_dirty_log_size = PML_ENTITY_NUM,
	// .update_cpu_dirty_logging = vmx_update_cpu_dirty_logging,

	// .nested_ops = &vmx_nested_ops,

	// .pi_update_irte = vmx_pi_update_irte,
	// .pi_start_assignment = vmx_pi_start_assignment,

	// #ifdef CONFIG_X86_64
	// .set_hv_timer = vmx_set_hv_timer,
	// .cancel_hv_timer = vmx_cancel_hv_timer,
	// #endif

	// .setup_mce = vmx_setup_mce,

	// #ifdef CONFIG_KVM_SMM
	// .smi_allowed = vmx_smi_allowed,
	// .enter_smm = vmx_enter_smm,
	// .leave_smm = vmx_leave_smm,
	// .enable_smi_window = vmx_enable_smi_window,
	// #endif

	// .can_emulate_instruction = vmx_can_emulate_instruction,
	// .apic_init_signal_blocked = vmx_apic_init_signal_blocked,
	// .migrate_timers = vmx_migrate_timers,

	// .msr_filter_changed = vmx_msr_filter_changed,
	// .complete_emulated_msr = kvm_complete_insn_gp,

	// .vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,
};

static struct kvm_x86_init_ops tyche_init_ops __initdata = {
	// .cpu_has_kvm_support = cpu_has_kvm_support,
	// .disabled_by_bios = vmx_disabled_by_bios,
	// .check_processor_compatibility = vmx_check_processor_compat,
	// .hardware_setup = hardware_setup,
	// .handle_intel_pt_intr = NULL,

	.runtime_ops = &tyche_x86_ops,
	// .pmu_ops = &intel_pmu_ops,
};

static void vmx_cleanup_l1d_flush(void)
{
	if (vmx_l1d_flush_pages) {
		free_pages((unsigned long)vmx_l1d_flush_pages, L1D_CACHE_ORDER);
		vmx_l1d_flush_pages = NULL;
	}
	/* Restore state so sysfs ignores VMX */
	l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_AUTO;
}

static void tyche_exit(void)
{
#if 0 // FIXME
#ifdef CONFIG_KEXEC_CORE
	RCU_INIT_POINTER(crash_vmclear_loaded_vmcss, NULL);
	synchronize_rcu();
#endif
#endif

	kvm_exit();

	vmx_cleanup_l1d_flush();

	allow_smaller_maxphyaddr = false;
}
module_exit(tyche_exit);

static int __init tyche_init(void)
{
	int r, cpu;

	r = kvm_init(&tyche_init_ops, sizeof(struct vcpu_tyche),
		     __alignof__(struct vcpu_tyche), THIS_MODULE);
	if (r)
		return r;
	
	/*
	 * Must be called after kvm_init() so enable_ept is properly set
	 * up. Hand the parameter mitigation value in which was stored in
	 * the pre module init parser. If no parameter was given, it will
	 * contain 'auto' which will be turned into the default 'cond'
	 * mitigation mode.
	 */
	r = vmx_setup_l1d_flush(vmentry_l1d_flush_param);
	if (r) {
		tyche_exit();
		return r;
	}

	vmx_setup_fb_clear_ctrl();

	for_each_possible_cpu(cpu) {
		INIT_LIST_HEAD(&per_cpu(loaded_vmcss_on_cpu, cpu));

#if 0 // FIXME: posted interrupt
		pi_init_cpu(cpu);
#endif
	}
#if 0 // FIXME
#ifdef CONFIG_KEXEC_CORE
	rcu_assign_pointer(crash_vmclear_loaded_vmcss,
			   crash_vmclear_local_loaded_vmcss);
#endif
#endif
	vmx_check_vmcs12_offsets();

	/*
	 * Shadow paging doesn't have a (further) performance penalty
	 * from GUEST_MAXPHYADDR < HOST_MAXPHYADDR so enable it
	 * by default
	 */
	if (!enable_ept)
		allow_smaller_maxphyaddr = true;

	return 0;
}
module_init(tyche_init);
