#include "tyche.h"

int write_domain_config(struct vcpu_vmx *vmx, usize core, register_group_t group, usize idx, usize value)
{
  struct kvm *kvm = vmx->vcpu.kvm;
  struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm); 
  
  // Check we have a domain.
  if (kvm_vmx->domain == NULL) {
    ERROR("The tyche domain is null");
    goto failure;
  }

  if (driver_set_domain_core_config(kvm_vmx->domain, core, group, idx, value) != SUCCESS) {
    ERROR("Unable to set the domain core config");
    goto failure;
  }
  return SUCCESS;
failure: 
  return FAILURE;
}
