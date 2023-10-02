#ifndef __KVM_X86_THEMIS_TYCHE_H
#define __KVM_X86_THEMIS_TYCHE_H

#include "common.h"
#include "tyche_capabilities_types.h"

#include "vmx.h"

/// Write the domain's core configuraiton field.
int write_domain_config(struct vcpu_vmx *vmx, register_group_t group, usize idx, usize value);

#endif
