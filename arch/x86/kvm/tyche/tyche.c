#include "tyche.h"
#include "x86.h"
#include "pmu.h"

MODULE_LICENSE("GPL");

// ———————————————————————————— External symbols ———————————————————————————— //
extern void tyche_debug_print(void);

// ————————————————————————————— PMU Operations ————————————————————————————— //
//TODO most of this can be imported from vmx I think.

static bool tyche_pmc_is_enabled (struct kvm_pmc *pmc)
{
  // TODO figure out.
  LOG("tyche_pmc_is_enabled");
  return false;
}

static struct kvm_pmc *tyche_pmc_idx_to_pmc(struct kvm_pmu *pmu, int pmc_idx)
{
  LOG("tyche_pmc_idx_to_pmc");
  return NULL;
}

static struct kvm_pmc *tyche_rdpmc_ecx_to_pmc(struct kvm_vcpu *vcpu,
		unsigned int idx, u64 *mask)
{
  LOG("tyche_rdpmc_ecx_to_pmc");
  return NULL;
}

static struct kvm_pmc *tyche_msr_idx_to_pmc(struct kvm_vcpu *vcpu, u32 msr)
{
  LOG("tyche msr idx to pmc");
  return NULL;
}

static	bool tyche_is_valid_rdpmc_ecx(struct kvm_vcpu *vcpu, unsigned int idx)
{
  LOG("tyche_is_valid_rdpmc_ecx");
  return false;
}

static bool tyche_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
  LOG("tyche_is_valid_msr");
  return false;
}


static int tyche_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
  LOG("tyche_get_msr");
  return -1;
}

static int tyche_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
  LOG("tyche_set_msr");
  return -1;
}

static void tyche_pmu_init(struct kvm_vcpu *vcpu)
{
  LOG("TODO: Intel pmu init called\n");
}

static void tyche_pmu_refresh(struct kvm_vcpu *vcpu)
{
  LOG("TODO: Intel pmu refresh called.\n");
}

static void tyche_pmu_reset(struct kvm_vcpu *vcpu)
{
  LOG("Intel PMU reset\n");
}

static void tyche_deliver_pmi(struct kvm_vcpu *vcpu)
{
  LOG("tyche_deliver_pmi");
}

static void tyche_pmu_cleanup(struct kvm_vcpu *vcpu)
{
  LOG("tyche_pmu_cleanup");
}


// ——————————————————————————— Global structures ———————————————————————————— //
struct vmcs_config vmcs_config;

struct kvm_pmu_ops tyche_pmu_ops __initdata = {
	.hw_event_available = false,//intel_hw_event_available,
	.pmc_is_enabled = tyche_pmc_is_enabled,
	.pmc_idx_to_pmc = tyche_pmc_idx_to_pmc,
	.rdpmc_ecx_to_pmc = tyche_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = tyche_msr_idx_to_pmc,
	.is_valid_rdpmc_ecx = tyche_is_valid_rdpmc_ecx,
	.is_valid_msr = tyche_is_valid_msr,
	.get_msr = tyche_get_msr,
	.set_msr = tyche_set_msr,
	.refresh = tyche_pmu_refresh,
  .init = tyche_pmu_init,
	.reset = tyche_pmu_reset,
	.deliver_pmi = tyche_deliver_pmi,
	.cleanup = tyche_pmu_cleanup,
};

//TODO this might be the source of the difference in CPUID?
struct kvm_x86_nested_ops tyche_nested_ops = {0};


// ———————————————————————————— Helper functions ———————————————————————————— //
static inline struct kvm_tyche *to_kvm_tyche(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tyche, kvm);
}

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
		return true; //nested;
	case MSR_AMD64_VIRT_SPEC_CTRL:
	case MSR_AMD64_TSC_RATIO:
		/* This is AMD only.  */
		return false;
	default:
		return true;
	}
}

static __init int tyche_cpu_has_kvm_support(void) {
  printk(KERN_ERR "In cpu has kvm support\n");
  //This has to be 1 otherwise kvm_init fails inside kvm_arch_init.
  return 1;
}

static __init int tyche_disabled_by_bios(void)
{
  printk(KERN_ERR "In tyche disabled by bios\n");
	return 0;
}


static __init int tyche_hardware_setup(void) {
  //TODO this could be used to call tyche, init the capabilities etc.
  //The original function in vmx seems to be setting a lot of constants.
  //We need to go line by line and understand what they are doing there.


  // Enable tyche mmu (which is basically no mmu).
  //kvm_enable_tyche_mmu();
  //TODO figure that out.
	//kvm_configure_mmu(1, 0, 4, 0);
  printk(KERN_ERR "In hardware setup\n");
  return 0;
}

static __init int tyche_check_processor_compat(void) {
  //TODO let's see what this does.
  printk(KERN_ERR "In check processor compat\n");
  return 0;
}

static __init unsigned int tyche_handle_intel_pt_intr(void)
{
  printk(KERN_ERR "In tyche_handle intel pt intr\n");
  return 0;
}

// ———————————————————————— Memory Helper Functions ————————————————————————— //

/// Called from the vcpu_pre_run to initialize a domain's resources.
/// Specifically, it goes through the kvm memory slots and performs the appropriate
/// capability operations to transfer memory resources to the VM domain.
/// TODO: for now, only do share operations.
static int setup_memory_capabilities(struct kvm* kvm)
{
  int i = 0, bkt = 0;
  struct kvm_tyche* tyche = NULL; to_kvm_tyche(kvm);
  if (kvm == NULL) {
    ERROR("The provided kvm structure is null.");
    goto failure;
  }
  // Extract the tyche domain.
  tyche = to_kvm_tyche(kvm);
  if (tyche == NULL || tyche->domain == NULL) {
    ERROR("No tyche domain found for the provided kvm struct.");
    goto failure;
  } 
  if (tyche->domain->state == DOMAIN_COMMITED) {
    ERROR("The domain is already committed!");
    goto failure;
  }

  // Go through the address spaces.
  // For each of them, inspect the kvm memory slots.
  // If they are valid ones (not RO or missing pfn), find contiguous segments
  // and perform a share/grant capability operation.
  mutex_lock(&kvm->slots_arch_lock);
  for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
    struct kvm_memslots * slots = __kvm_memslots(kvm, i);
    struct kvm_memory_slot *slot = NULL;

    kvm_for_each_memslot(slot, bkt, slots) {
      usize paddr = 0, vaddr = 0, size = 0;
      kvm_pfn_t pfn = gfn_to_pfn_memslot(slot, slot->base_gfn);
      if (pfn == KVM_PFN_NOSLOT || pfn == KVM_PFN_ERR_RO_FAULT) {
        // For the moment ignore these entries.
        continue;
      }
      // We are going through the physical address space that corresponds
      // to this domain's kvm memory slots. The goal is to identify "gaps", i.e.,
      // non contiguous physical memory pages. Everytime we have a gap, we need
      // to perform a different tyche driver capability call to transfer the right
      // portion of physical memory.
      // Note: with transparent hugepages enabled in the kernel, we should see
      // very few gaps ( < 10) for a the default linux VM, and < 40 in regular 
      // kvm virtual machines.
      // start and size below represent a contiguous segment of physical memory.
      paddr = pfn;
      vaddr = slot->userspace_addr;
      size = 1;
      for (i = 0; i < slot->npages; i++) {
        gfn_t gfn = slot->base_gfn + i;
        kvm_pfn_t npfn = gfn_to_pfn_memslot(slot, gfn);
        if (npfn != pfn) {
          // There is a gap in the address space, call tyche.
          if (driver_add_raw_segment(tyche->domain, vaddr, paddr, size) != SUCCESS) {
            ERROR("Unable to add the segment to the domain.");
            goto failure;
          }
          // Update the address space.
          paddr = npfn;
          vaddr = vaddr + size;
          size = 1;
          continue;
        }
        // Contiguous entry, keep going.
        size++;
      }
      // Sanity check.
      if (i != slot->npages) {
        ERROR("Why is the loop not going till the end?");
        goto failure;
      }
      // Register last segment.
      if (driver_add_raw_segment(tyche->domain, vaddr, paddr, size) != SUCCESS) {
        ERROR("Unable to register last segment!");
        goto failure;
      }
    }
  }
  mutex_unlock(&kvm->slots_arch_lock);
  
  // TODO: should also do the mprotects... Not sure yet how.
  // We might have to go through the kvm memory slots a second time.
  // Or we could do it in the loop above.

  // All done, return!
  return SUCCESS;
failure:
  return FAILURE;
}

// ————————————————————————————————— Hooks —————————————————————————————————— //
/// Creates a domain vm.
static int tyche_vm_init(struct kvm *kvm) {
  struct kvm_tyche *tyche = to_kvm_tyche(kvm);
  if (driver_create_domain(NULL, &(tyche->domain)) != SUCCESS) {
    ERROR("Unable to create a new domain.");
    return -1;
  }
  trace_printk("Successfully created a new domain %p\n", tyche->domain);
  return 0;
}

static void tyche_vm_destroy(struct kvm *kvm)
{
  struct kvm_tyche *tyche = to_kvm_tyche(kvm);
  if (driver_delete_domain(tyche->domain) != SUCCESS) {
    ERROR("Unable to delete the domain %p", tyche->domain);
    return;
  }
  trace_printk("Deleted domain successfully.\n");
}

static int tyche_vcpu_precreate(struct kvm *kvm)
{
  //TODO some of the ipi must be initialized here I guess.
  //Need to look into it.
	//return vmx_alloc_ipiv_pid_table(kvm);
  trace_printk("In vcpu pre create %d.\n", kvm->created_vcpus);
  return 0;
}


static int tyche_vcpu_create(struct kvm_vcpu *vcpu)
{
  trace_printk("In vcpu create %p, %d\n", vcpu->arch.walk_mmu, vcpu->kvm->created_vcpus);
  //TODO: kvm will keep track of all the vcpus for us.
  //What we can do here, is keep the state of the vcpu inside a tyche_vcpu.
  //Then, when we reach the first run, we check if the domain has been sealed.
  //If not, we know that we have to initialize everything.
  //For each vcpu (except the first one), we will duplicate the transition
  //capability (and thus have a separate context).
  return 0;
}

static int tyche_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
  struct kvm* kvm = vcpu->kvm;
  if (setup_memory_capabilities(kvm) != SUCCESS) {
    ERROR("Unable to setup the memory capabilities for the vm");
    return FAILURE;
  }
  return SUCCESS;
}

static void tyche_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
  trace_printk("Vcpu reset %p\n", vcpu->arch.walk_mmu);
}

// ———————————————————————————— Memory Functions ———————————————————————————— //



static void tyche_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level)
{
  trace_printk("In the load mmup pgd: %p\n", vcpu->arch.walk_mmu); 
}
// ———————————————————————————————— x86 Ops ————————————————————————————————— //
static struct kvm_x86_ops tyche_x86_ops __initdata = {
	.name = "tyche_intel",

	.hardware_unsetup = NULL,

	.hardware_enable = NULL,
	.hardware_disable = NULL,
	.has_emulated_msr = NULL, //tyche_has_emulated_msr,

	.vm_size = sizeof(struct kvm_tyche),
	.vm_init = NULL, //tyche_vm_init,
	.vm_destroy = NULL, //tyche_vm_destroy,

	.vcpu_precreate = NULL, //tyche_vcpu_precreate,
	.vcpu_create = NULL, //tyche_vcpu_create,
	.vcpu_free = NULL, //vmx_vcpu_free,
	.vcpu_reset = NULL, //tyche_vcpu_reset,

	.prepare_switch_to_guest = NULL,// vmx_prepare_switch_to_guest,
	.vcpu_load = NULL, //tyche_vcpu_load,
	.vcpu_put = NULL, //vmx_vcpu_put,

	.update_exception_bitmap = NULL, //tyche_update_exception_bitmap,
	.get_msr_feature = NULL, //tyche_get_msr_feature,
	.get_msr = NULL, //tyche_get_msr,
	.set_msr = NULL, //vmx_set_msr,
	.get_segment_base = NULL, // vmx_get_segment_base,
	.get_segment = NULL, //vmx_get_segment,
	.set_segment = NULL, //vmx_set_segment,
	.get_cpl = NULL, //vmx_get_cpl,
	.get_cs_db_l_bits = NULL, //vmx_get_cs_db_l_bits,
	.set_cr0 = NULL, //vmx_set_cr0,
	.is_valid_cr4 = NULL, //vmx_is_valid_cr4,
	.set_cr4 = NULL, //vmx_set_cr4,
	.set_efer = NULL, //vmx_set_efer,
	.get_idt = NULL, // tyche_get_idt,
	.set_idt = NULL, // tyche_set_idt,
	.get_gdt = NULL, // tyche_get_gdt,
	.set_gdt = NULL, // tyche_set_gdt,
	.set_dr7 = NULL, // tyche_set_dr7,
	.sync_dirty_debug_regs = NULL, //vmx_sync_dirty_debug_regs,
	.cache_reg = NULL, //vmx_cache_reg,
	.get_rflags = NULL, // vmx_get_rflags,
	.set_rflags = NULL, // vmx_set_rflags,
	.get_if_flag = NULL, // vmx_get_if_flag,

	.flush_tlb_all = NULL, //vmx_flush_tlb_all,
	.flush_tlb_current = NULL, //vmx_flush_tlb_current,
	.flush_tlb_gva = NULL, //vmx_flush_tlb_gva,
	.flush_tlb_guest = NULL,// vmx_flush_tlb_guest,

	.vcpu_pre_run = tyche_vcpu_pre_run,
	.vcpu_run = NULL, // vmx_vcpu_run,
	.handle_exit = NULL, //vmx_handle_exit,
	.skip_emulated_instruction = NULL, // vmx_skip_emulated_instruction,
	.update_emulated_instruction = NULL, //vmx_update_emulated_instruction,
	.set_interrupt_shadow = NULL, //vmx_set_interrupt_shadow,
	.get_interrupt_shadow = NULL, //vmx_get_interrupt_shadow,
	.patch_hypercall = NULL, //vmx_patch_hypercall,
	.inject_irq = NULL, //vmx_inject_irq,
	.inject_nmi = NULL, //vmx_inject_nmi,
	.inject_exception = NULL, // vmx_inject_exception,
	.cancel_injection = NULL, // vmx_cancel_injection,
	.interrupt_allowed = NULL, //vmx_interrupt_allowed,
	.nmi_allowed = NULL, //vmx_nmi_allowed,
	.get_nmi_mask = NULL, // vmx_get_nmi_mask,
	.set_nmi_mask = NULL, //vmx_set_nmi_mask,
	.enable_nmi_window = NULL, //vmx_enable_nmi_window,
	.enable_irq_window = NULL, //vmx_enable_irq_window,
	.update_cr8_intercept = NULL, // vmx_update_cr8_intercept,
	.set_virtual_apic_mode = NULL, //vmx_set_virtual_apic_mode,
	.set_apic_access_page_addr = NULL, //vmx_set_apic_access_page_addr,
	.refresh_apicv_exec_ctrl = NULL, //vmx_refresh_apicv_exec_ctrl,
	.load_eoi_exitmap = NULL, //vmx_load_eoi_exitmap,
	.apicv_post_state_restore = NULL, // vmx_apicv_post_state_restore,
	.check_apicv_inhibit_reasons = NULL, //vmx_check_apicv_inhibit_reasons,
	.hwapic_irr_update = NULL, //vmx_hwapic_irr_update,
	.hwapic_isr_update = NULL, //vmx_hwapic_isr_update,
	.guest_apic_has_interrupt = NULL, //vmx_guest_apic_has_interrupt,
	.sync_pir_to_irr = NULL, //vmx_sync_pir_to_irr,
	.deliver_interrupt = NULL, //vmx_deliver_interrupt,
	.dy_apicv_has_pending_interrupt = NULL, //pi_has_pending_interrupt,

	.set_tss_addr = NULL, //vmx_set_tss_addr,
	.set_identity_map_addr = NULL, // vmx_set_identity_map_addr,
	.get_mt_mask =  NULL, //vmx_get_mt_mask,

	.get_exit_info =  NULL, //vmx_get_exit_info,

	.vcpu_after_set_cpuid =  NULL, //vmx_vcpu_after_set_cpuid,

	.has_wbinvd_exit =  NULL, //cpu_has_vmx_wbinvd_exit,

	.get_l2_tsc_offset =  NULL, //vmx_get_l2_tsc_offset,
	.get_l2_tsc_multiplier =  NULL, //vmx_get_l2_tsc_multiplier,
	.write_tsc_offset =  NULL, //vmx_write_tsc_offset,
	.write_tsc_multiplier =  NULL, //vmx_write_tsc_multiplier,

	.load_mmu_pgd =  NULL, //tyche_load_mmu_pgd,

	.check_intercept = NULL, //vmx_check_intercept,
	.handle_exit_irqoff = NULL, // vmx_handle_exit_irqoff,

	.request_immediate_exit = NULL, //vmx_request_immediate_exit,

	.sched_in =  NULL, //vmx_sched_in,

	.cpu_dirty_log_size =  0, //PML_ENTITY_NUM,
	.update_cpu_dirty_logging = NULL, // vmx_update_cpu_dirty_logging,

	.nested_ops = &tyche_nested_ops,

	.pi_update_irte =  NULL, //vmx_pi_update_irte,
	.pi_start_assignment =  NULL, //vmx_pi_start_assignment,

	#ifdef CONFIG_X86_64
	.set_hv_timer = NULL, // vmx_set_hv_timer,
	.cancel_hv_timer = NULL, //vmx_cancel_hv_timer,
	#endif

	.setup_mce = NULL, //vmx_setup_mce,

	#ifdef CONFIG_KVM_SMM
	.smi_allowed = NULL, //vmx_smi_allowed,
	.enter_smm = NULL, //vmx_enter_smm,
	.leave_smm = NULL, //vmx_leave_smm,
	.enable_smi_window = NULL, //vmx_enable_smi_window,
	#endif

	.can_emulate_instruction = NULL, // vmx_can_emulate_instruction,
	.apic_init_signal_blocked = NULL, //vmx_apic_init_signal_blocked,
	.migrate_timers =  NULL, //vmx_migrate_timers,

	.msr_filter_changed = NULL, //vmx_msr_filter_changed,
	.complete_emulated_msr = NULL, //kvm_complete_insn_gp,

	.vcpu_deliver_sipi_vector = NULL, //kvm_vcpu_deliver_sipi_vector,
};

static struct kvm_x86_init_ops tyche_init_ops __initdata = {
	.cpu_has_kvm_support = tyche_cpu_has_kvm_support,
  .disabled_by_bios = tyche_disabled_by_bios,
	.check_processor_compatibility = tyche_check_processor_compat,
	.hardware_setup = tyche_hardware_setup,
	.handle_intel_pt_intr = tyche_handle_intel_pt_intr,

	.runtime_ops = &tyche_x86_ops,
	.pmu_ops = &tyche_pmu_ops,
};

static void kvm_tyche_exit(void)
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
module_exit(kvm_tyche_exit);

static int __init kvm_tyche_init(void)
{
	int r;
	r = kvm_init(&tyche_init_ops, sizeof(struct vcpu_tyche),
		     __alignof__(struct vcpu_tyche), THIS_MODULE);
	if (r)
		return r;
  trace_printk("Done with the kvm_tyche_init\n");
	return 0;
}
module_init(kvm_tyche_init);
