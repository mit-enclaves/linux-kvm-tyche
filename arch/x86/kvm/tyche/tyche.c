#include "tyche.h"
#include "nested.h"
#include "vmcs12.h"
#include "pmu.h"

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

//void tyche_update_exception_bitmap(struct kvm_vcpu *vcpu)
//{
//	u32 eb;
//
//	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
//	     (1u << DB_VECTOR) | (1u << AC_VECTOR);
//	/*
//	 * Guest access to VMware backdoor ports could legitimately
//	 * trigger #GP because of TSS I/O permission bitmap.
//	 * We intercept those #GP and allow access to them anyway
//	 * as VMware does.
//	 */
//	if (enable_vmware_backdoor)
//		eb |= (1u << GP_VECTOR);
//	if ((vcpu->guest_debug &
//	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
//	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
//		eb |= 1u << BP_VECTOR;
//	if (to_tyche(vcpu)->rmode.vm86_active)
//		eb = ~0;
//	if (!vmx_need_pf_intercept(vcpu))
//		eb &= ~(1u << PF_VECTOR);
//
//	/* When we are running a nested L2 guest and L1 specified for it a
//	 * certain exception bitmap, we must trap the same exceptions and pass
//	 * them to L1. When running L2, we will only handle the exceptions
//	 * specified above if L1 did not want them.
//	 */
//	if (is_guest_mode(vcpu))
//		eb |= get_vmcs12(vcpu)->exception_bitmap;
//        else {
//		int mask = 0, match = 0;
//
//		if (enable_ept && (eb & (1u << PF_VECTOR))) {
//			/*
//			 * If EPT is enabled, #PF is currently only intercepted
//			 * if MAXPHYADDR is smaller on the guest than on the
//			 * host.  In that case we only care about present,
//			 * non-reserved faults.  For vmcs02, however, PFEC_MASK
//			 * and PFEC_MATCH are set in prepare_vmcs02_rare.
//			 */
//			mask = PFERR_PRESENT_MASK | PFERR_RSVD_MASK;
//			match = PFERR_PRESENT_MASK;
//		}
//		tyche_vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, mask);
//		tyche_vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, match);
//	}
//
//	/*
//	 * Disabling xfd interception indicates that dynamic xfeatures
//	 * might be used in the guest. Always trap #NM in this case
//	 * to save guest xfd_err timely.
//	 */
//	if (vcpu->arch.xfd_no_write_intercept)
//		eb |= (1u << NM_VECTOR);
//
//	tyche_vmcs_write32(EXCEPTION_BITMAP, eb);
//}

// ————————————————————————— AGHOSN Implementations ————————————————————————— //

struct kvm_pmu_ops tyche_pmu_ops __initdata = {
	.hw_event_available = 0x1,//intel_hw_event_available,
	.pmc_is_enabled = 0x2,//intel_pmc_is_enabled,
	.pmc_idx_to_pmc = 0x3, //intel_pmc_idx_to_pmc,
	.rdpmc_ecx_to_pmc = 0x4, //intel_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = 0x5, //intel_msr_idx_to_pmc,
	.is_valid_rdpmc_ecx = 0x6, //intel_is_valid_rdpmc_ecx,
	.is_valid_msr = 0x7, //intel_is_valid_msr,
	.get_msr = 0x8, //intel_pmu_get_msr,
	.set_msr = 0x9, //intel_pmu_set_msr,
	.refresh = 0xa, //intel_pmu_refresh,
	.init = 0xb ,//intel_pmu_init,
	.reset = 0xc, // intel_pmu_reset,
	.deliver_pmi = 0xd, //intel_pmu_deliver_pmi,
	.cleanup = 0xe, // intel_pmu_cleanup,
};


/*
 * The kvm parameter can be NULL (module initialization, or invocation before
 * VM creation). Be sure to check the kvm parameter before using it.
 */
static bool tyche_has_emulated_msr(struct kvm *kvm, u32 index)
{
	switch (index) {
	case MSR_IA32_SMBASE:
		if (!IS_ENABLED(CONFIG_KVM_SMM))
			return false;
		/*
		 * We cannot do SMM unless we can run the guest in big
		 * real mode.
		 */
		return false; //enable_unrestricted_guest || emulate_invalid_guest_state;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		return false; //nested;
	case MSR_AMD64_VIRT_SPEC_CTRL:
	case MSR_AMD64_TSC_RATIO:
		/* This is AMD only.  */
		return false;
	default:
		return true;
	}
}

static __init int tyche_cpu_has_kvm_support(void ) {
  //This has to be 1 otherwise kvm_init fails inside kvm_arch_init.
  return 1;
}

static __init int tyche_disabled_by_bios(void)
{
	return 0;
}


static __init int hardware_setup(void) {
  //TODO this could be used to call tyche, init the capabilities etc.
  //The original function in vmx seems to be setting a lot of constants.
  //We need to go line by line and understand what they are doing there.
  printk(KERN_NOTICE "In tyche hardware setup\n\n");
  return 0;
}

static __init int tyche_check_processor_compat(void) {
  //TODO let's see what this does.
  return 0;
}

static struct kvm_x86_ops tyche_x86_ops __initdata = {
	.name = "tyche_intel",

	// .hardware_unsetup = vmx_hardware_unsetup,

	// .hardware_enable = vmx_hardware_enable,
	// .hardware_disable = vmx_hardware_disable,
	.has_emulated_msr = tyche_has_emulated_msr,

	.vm_size = sizeof(struct kvm_tyche),
	// .vm_init = vmx_vm_init,
	// .vm_destroy = vmx_vm_destroy,

	// .vcpu_precreate = vmx_vcpu_precreate,
	// .vcpu_create = vmx_vcpu_create,
	// .vcpu_free = vmx_vcpu_free,
	// .vcpu_reset = vmx_vcpu_reset,

	// .prepare_switch_to_guest = vmx_prepare_switch_to_guest,
	//.vcpu_load = tyche_vcpu_load,
	// .vcpu_put = vmx_vcpu_put,

	//.update_exception_bitmap = tyche_update_exception_bitmap,
	//.get_msr_feature = tyche_get_msr_feature,
	//.get_msr = tyche_get_msr,
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
	//.get_idt = tyche_get_idt,
	//.set_idt = tyche_set_idt,
	//.get_gdt = tyche_get_gdt,
	//.set_gdt = tyche_set_gdt,
	//.set_dr7 = tyche_set_dr7,
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
	.cpu_has_kvm_support = tyche_cpu_has_kvm_support,
  .disabled_by_bios = tyche_disabled_by_bios,
	.check_processor_compatibility = tyche_check_processor_compat,
	.hardware_setup = hardware_setup,
	// .handle_intel_pt_intr = NULL,

	.runtime_ops = &tyche_x86_ops,
	.pmu_ops = &tyche_pmu_ops,
};

static void tyche_exit(void)
{
#if 0 // FIXME
#ifdef CONFIG_KEXEC_CORE
	RCU_INIT_POINTER(crash_vmclear_loaded_vmcss, NULL);
	synchronize_rcu();
#endif
#endif

	kvm_exit();

	//vmx_cleanup_l1d_flush();

	allow_smaller_maxphyaddr = false;
}
module_exit(tyche_exit);

static int __init tyche_init(void)
{
	int r, cpu;
	r = kvm_init(&tyche_init_ops, sizeof(struct vcpu_tyche),
		     __alignof__(struct vcpu_tyche), THIS_MODULE);
  trace_printk("Done with kvm_init\n");
	if (r)
		return r;
	
  trace_printk("Done with tyche_init\n");
	return 0;
}
module_init(tyche_init);
