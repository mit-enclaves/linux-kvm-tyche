#include "tyche.h"
#include "vmx.h"
#include "../mmu/mmu_internal.h"

int write_domain_config(struct vcpu_vmx *vmx, usize idx, usize value)
{
  struct kvm *kvm = vmx->vcpu.kvm;
  struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm);
  
  // Check we have a domain.
  if (kvm_vmx->domain == NULL) {
    ERROR("The tyche domain is null");
    goto failure;
  }

  if (driver_set_domain_core_config(kvm_vmx->domain, vmx->vcpu.vcpu_id, idx, value) != SUCCESS) {
    ERROR("Unable to set the domain core config");
    goto failure;
  }
  return SUCCESS;
failure: 
  // TODO error here?
  return FAILURE;
}

usize read_domain_config(struct vcpu_vmx *vmx, usize idx)
{
  usize value = 0;
  struct kvm *kvm = vmx->vcpu.kvm;
  struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm);
  
  // Check we have a domain.
  if (kvm_vmx->domain == NULL) {
    ERROR("The tyche domain is null");
    goto failure;
  }
  if (driver_get_domain_core_config(
        kvm_vmx->domain, vmx->vcpu.vcpu_id, idx, &value) != SUCCESS) {
    ERROR("Unable to get the domain core config.");
    goto failure;
  }
  return value;
failure:
  printk(KERN_ERR "Failed to read domain configuration.\n");
  return 0;
}

void clear_bits_domain_config(struct vcpu_vmx *vmx, usize field, usize mask)
{
  write_domain_config(vmx, field, read_domain_config(vmx, field) & ~mask);
}

void set_bits_domain_config(struct vcpu_vmx *vmx, usize field, usize mask)
{
	write_domain_config(vmx, field, read_domain_config(vmx, field) | mask);
}

// ————————————————————————— MMU-related Functions —————————————————————————— //

static int mmu_pages_are_contiguous(struct kvm_memory_slot *slot, bool write) {
  kvm_pfn_t pfn = __gfn_to_pfn_memslot(slot, slot->base_gfn,
        false, false, NULL, write, NULL, NULL);
  gfn_t base_gfn = slot->base_gfn;
  usize vaddr = slot->userspace_addr;
  int i = 0;
  //TODO(aghosn) check these as well:
  if (pfn == KVM_PFN_NOSLOT || pfn == KVM_PFN_ERR_RO_FAULT) {
    // For the moment ignore these entries.
    pr_err("Wrong type of memory segment %llx\n", pfn);
    return 0;
  }
  for (i = 1; i < slot->npages; i++) {
    gfn_t gfn = slot->base_gfn + i; 
    kvm_pfn_t npfn = __gfn_to_pfn_memslot(slot, slot->base_gfn+i,
        false, false, NULL, write, NULL, NULL);
    if (npfn != (pfn + i)) {
      pr_err("The pages are not contiguous.\n");
      pr_err("Expected %llx, got %llx\n", pfn + i, npfn);
      return 0;
    }
  }
  return 1;
}

/// Add a mapping for the domain.
/// Inspired by kvm_tdp_mmu_map.
int tyche_mmu_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
  struct kvm_mmu *mmu = vcpu->arch.mmu;
  struct kvm *kvm = vcpu->kvm;
  int ret = RET_PF_FIXED;
  kvm_pfn_t pfn = 0;
  //boot wprot = false;

  //TODO(aghosn) Not sure we need this.
  //kvm_mmu_hugepage_adjust(vcpu, fault);
  //trace_kvm_mmu_spte_requested(fault);

  struct kvm_vmx *vmx = to_kvm_vmx(kvm);
  if (vmx->domain == NULL) {
    ERROR("Embedded domain is null");
    return RET_PF_INVALID;
  }

  rcu_read_lock();

  if (unlikely(!fault->slot)) {
    ERROR("This is probably mmio.");
    rcu_read_unlock();
    BUG_ON(1);
  }

  if (!mmu_pages_are_contiguous(fault->slot, fault->write)) {
    ERROR("Pages are not contiguous!");
    BUG_ON(1);
  }
  
  pfn =  __gfn_to_pfn_memslot(fault->slot, fault->slot->base_gfn,
        false, false, NULL, fault->write, NULL, NULL);
  if (driver_add_raw_segment(vmx->domain, fault->slot->userspace_addr,
        pfn << PAGE_SHIFT, fault->slot->npages << PAGE_SHIFT) != SUCCESS) {
    ERROR("Unable to add a raw segment");
    rcu_read_unlock();
    BUG_ON(1);
  }
  // Set the protections for the segment.
  if (driver_mprotect_domain(vmx->domain, fault->slot->userspace_addr,
        fault->slot->npages << PAGE_SHIFT,
        MEM_READ|MEM_WRITE|MEM_EXEC|MEM_SUPER|MEM_ACTIVE, SHARED,
        (fault->slot->base_gfn) << PAGE_SHIFT) != SUCCESS) {
    ERROR("Unable to mprotec the segment.");
    rcu_read_unlock();
    BUG_ON(1);
  }
  // Should commit the segment.
  if (driver_commit_regions(vmx->domain) != SUCCESS) {
    ERROR("Failed to commit the regions for the domain");
    rcu_read_unlock();
    BUG_ON(1);
  }
 
  pr_err("[PF mapped] hpa: %llx, gpa: %llx, hva: %lx | npages: %ld\n",
      pfn << PAGE_SHIFT, fault->slot->base_gfn << PAGE_SHIFT, fault->slot->userspace_addr,
      fault->slot->npages);
unlock:
  rcu_read_unlock();
  return ret;
}
