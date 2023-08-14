#ifndef __TYCHE_X86_VMX_NESTED_H
#define __TYCHE_X86_VMX_NESTED_H

#include "tyche.h"

int tyche_get_vmx_msr(struct nested_vmx_msrs *msrs, u32 msr_index, u64 *pdata);
int tyche_set_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data);

#endif
