#include "tyche.h"

#include <asm/desc.h>
#include <asm/virtext.h>

#define KVM_VM_CR0_ALWAYS_OFF (X86_CR0_NW | X86_CR0_CD)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR0_NE
#define KVM_VM_CR0_ALWAYS_ON				\
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)

#define KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR4_VMXE
#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

#define MSR_IA32_RTIT_STATUS_MASK (~(RTIT_STATUS_FILTEREN | \
	RTIT_STATUS_CONTEXTEN | RTIT_STATUS_TRIGGEREN | \
	RTIT_STATUS_ERROR | RTIT_STATUS_STOPPED | \
	RTIT_STATUS_BYTECNT))

static bool tyche_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	/*
	 * We operate under the default treatment of SMM, so VMX cannot be
	 * enabled under SMM.  Note, whether or not VMXE is allowed at all,
	 * i.e. is a reserved bit, is handled by common x86 code.
	 */
	if ((cr4 & X86_CR4_VMXE) && is_smm(vcpu))
		return false;

#if 0  // FIXME: skip nested for now
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
			secondary_exec_controls_setbit(vmx, SECONDARY_EXEC_DESC);
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
	// .get_msr_feature = vmx_get_msr_feature,
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
