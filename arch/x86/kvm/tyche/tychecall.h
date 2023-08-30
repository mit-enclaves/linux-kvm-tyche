#ifndef __KVM_X86_TYCHE_TYCHECALL_H
#define __KVM_X86_TYCHE_TYCHECALL_H

#include <linux/nospec.h>

#include "domains.h"

#define TYCHE_SWITCH_NEW_VCPU 3

// Tyche calls interface

int tyche_create_domain(domain_handle_t handle, driver_domain_t **ptr);

int tyche_set_traps(driver_domain_t *dom, usize traps);

int tyche_set_cores(driver_domain_t *dom, usize core_map);

int tyche_set_perm(driver_domain_t *dom, usize perm);

int tyche_set_switch(driver_domain_t *dom, usize sw);

int tyche_set_entry_on_core(driver_domain_t *dom, usize core, usize cr3, usize rip, usize rsp);

int tyche_set_vmcs_field(driver_domain_t *handle, usize field, usize value);

int tyche_commit_domain(driver_domain_t *dom);

#endif
