#ifndef __KVM_X86_THEMIS_TYCHE_H
#define __KVM_X86_THEMIS_TYCHE_H

#include "common.h"
#include "tyche_capabilities_types.h"

#include "vmx.h"

/// Write the domain's core configuration field.
int write_domain_config(struct vcpu_vmx *vmx, usize idx, usize value);

/// Read the domain's core configuration field.
usize read_domain_config(struct vcpu_vmx *vmx, usize idx);
#endif
