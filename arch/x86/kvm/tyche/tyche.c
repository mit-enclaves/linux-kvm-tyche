#include "tyche.h"
#include "x86.h"
#include "pmu.h"

MODULE_LICENSE("GPL");

// ————————————————————————————— PMU Operations ————————————————————————————— //
//TODO most of this can be imported from vmx I think.
//See with @yuchen.
static void intel_pmu_init(struct kvm_vcpu *vcpu)
{
  trace_printk("TODO: Intel pmu init called\n");
}

static void intel_pmu_refresh(struct kvm_vcpu *vcpu)
{
  trace_printk("TODO: Intel pmu refresh called.\n");
}

// ——————————————————————————— Global structures ———————————————————————————— //
struct vmcs_config vmcs_config;

struct kvm_pmu_ops tyche_pmu_ops __initdata = {
	.hw_event_available = 0x1dead,//intel_hw_event_available,
	.pmc_is_enabled = 0x2dead,//intel_pmc_is_enabled,
	.pmc_idx_to_pmc = 0x3dead, //intel_pmc_idx_to_pmc,
	.rdpmc_ecx_to_pmc = 0x4dead, //intel_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = 0x5dead, //intel_msr_idx_to_pmc,
	.is_valid_rdpmc_ecx = 0x6dead, //intel_is_valid_rdpmc_ecx,
	.is_valid_msr = 0x7dead, //intel_is_valid_msr,
	.get_msr = 0x8dead, //intel_pmu_get_msr,
	.set_msr = 0x9dead, //intel_pmu_set_msr,
	.refresh = intel_pmu_refresh,
  .init = intel_pmu_init,
	.reset = 0xcdead, // intel_pmu_reset,
	.deliver_pmi = 0xddead, //intel_pmu_deliver_pmi,
	.cleanup = 0xedead, // intel_pmu_cleanup,
};

struct kvm_x86_nested_ops tyche_nested_ops = {0};


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

static __init int tyche_cpu_has_kvm_support(void) {
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
  return 0;
}

static __init int tyche_check_processor_compat(void) {
  //TODO let's see what this does.
  return 0;
}

static int tyche_vm_init(struct kvm *kvm) {
  trace_printk("Inside the tyche_vm_init\n");
  return 0;
}

static struct kvm_x86_ops tyche_x86_ops __initdata = {
	.name = "tyche_intel",

	// .hardware_unsetup = vmx_hardware_unsetup,

	// .hardware_enable = vmx_hardware_enable,
	// .hardware_disable = vmx_hardware_disable,
	.has_emulated_msr = tyche_has_emulated_msr,

  //TODO aghosn this is the reason why it's broken.
	.vm_size = sizeof(struct kvm_tyche),
	.vm_init = tyche_vm_init,
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

	.nested_ops = &tyche_nested_ops,

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
	int r;
	r = kvm_init(&tyche_init_ops, sizeof(struct vcpu_tyche),
		     __alignof__(struct vcpu_tyche), THIS_MODULE);
	if (r)
		return r;
  
	return 0;
}
module_init(tyche_init);
