#ifndef __KVM_X86_THEMIS_TYCHE_H
#define __KVM_X86_THEMIS_TYCHE_H

#include "common.h"
#include "common_log.h"
#include "tyche_capabilities_types.h"

#include "vmx.h"

//TODO(aghosn): both macros are disabled for now because linux complains
//that we call them with irq disabled and rw_semaphores can sleep.
#define ACQUIRE_DOM(dom, write)                                            \
	do {                                                               \
		if (in_interrupt()) {                                      \
			printk(KERN_ERR "In interrupt at %s:%d", __FILE__, \
			       __LINE__);                                  \
		}                                                          \
		if (write) {                                               \
			/*down_write(&(dom->rwlock));*/                    \
		} else {                                                   \
			/*down_read(&(dom->rwlock));*/                     \
		}                                                          \
	} while (0);

#define RELEASE_DOM(dom, write)                                            \
	do {                                                               \
		if (in_interrupt()) {                                      \
			printk(KERN_ERR "In interrupt at %s:%d", __FILE__, \
			       __LINE__);                                  \
		}                                                          \
		if (write) {                                               \
			/*up_write(&(dom->rwlock));*/                      \
		} else {                                                   \
			/*up_read(&(dom->rwlock));*/                       \
		}                                                          \
	} while (0);

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

/// Delete the domain's region following a change of memoryslots.
int tyche_delete_regions(struct kvm *kvm);

/// Debugging function, remove later on.
void tyche_print_all_slots(struct kvm_vcpu *vcpu);

#endif
