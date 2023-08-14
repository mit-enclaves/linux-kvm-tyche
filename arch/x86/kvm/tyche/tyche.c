#include "tyche.h"
#include "nested.h"

#include <asm/desc.h>
#include <asm/virtext.h>
#include <asm/msr-index.h>

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
 * If nested=1, nested virtualization is supported, i.e., guests may use
 * VMX and be a hypervisor for its own guests. If nested=0, guests may not
 * use VMX instructions.
 */
static bool __read_mostly nested = 1;
module_param(nested, bool, S_IRUGO);

/* Control for disabling CPU Fill buffer clear */
static bool __read_mostly vmx_fb_clear_ctrl_available;

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
	// .vcpu_load = vmx_vcpu_load,
	// .vcpu_put = vmx_vcpu_put,

	// .update_exception_bitmap = vmx_update_exception_bitmap,
	.get_msr_feature = tyche_get_msr_feature,
	// .get_msr = vmx_get_msr,
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
	// .set_dr7 = vmx_set_dr7,
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
