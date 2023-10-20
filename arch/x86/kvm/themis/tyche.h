#ifndef __KVM_X86_THEMIS_TYCHE_H
#define __KVM_X86_THEMIS_TYCHE_H

#include "common.h"
#include "tyche_capabilities_types.h"

#include "vmx.h"

/// Write the domain's core configuration field.
int write_domain_config(struct vcpu_vmx *vmx, usize idx, usize value);

/// Read the domain's core configuration field.
usize read_domain_config(struct vcpu_vmx *vmx, usize idx);

/// Install the mapping following a page fault.
int tyche_mmu_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
#endif
