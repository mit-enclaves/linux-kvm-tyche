#ifndef __KVM_X86_THEMIS_TYCHE_H
#define __KVM_X86_THEMIS_TYCHE_H

#include "common.h"
#include "tyche_capabilities_types.h"

#include "vmx.h"

/// Write the domain's core configuration field.
int write_domain_config(struct vcpu_vmx *vmx, usize idx, usize value);

/// Read the domain's core configuration field.
usize read_domain_config(struct vcpu_vmx *vmx, usize idx);

/// Clear the bits.
void clear_bits_domain_config(struct vcpu_vmx *vmx, usize field, usize mask);

/// Set the bits.
void set_bits_domain_config(struct vcpu_vmx *vmx, usize field, usize mask);

/// Read a domain's general purpose register.
usize read_domain_register(struct vcpu_vmx *vmx, int reg);

/// Write a domain's general purpose register.
int write_domain_register(struct vcpu_vmx *vmx, int reg, usize val);

/// Dump all the tyche gp registers.
void read_all_gp_registers(struct vcpu_vmx *vmx);

/// Sync all the tyche gp registers.
void write_all_gp_registers(struct vcpu_vmx *vmx);

/// Install the mapping following a page fault.
int tyche_mmu_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);

#endif
