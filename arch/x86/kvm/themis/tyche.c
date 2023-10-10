#include "tyche.h"

int write_domain_config(struct vcpu_vmx *vmx, usize idx, usize value)
{
  struct kvm *kvm = vmx->vcpu.kvm;
  struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm);
  
  // Check we have a domain.
  if (kvm_vmx->domain == NULL) {
    ERROR("The tyche domain is null");
    goto failure;
  }

  if (driver_set_domain_core_config(kvm_vmx->domain, vmx->vpid, idx, value) != SUCCESS) {
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
        kvm_vmx->domain, vmx->vpid, idx, &value) != SUCCESS) {
    ERROR("Unable to get the domain core config.");
    goto failure;
  }
  return value;
failure:
  printk(KERN_ERR "Failed to read domain configuration.\n");
  return 0;
}
