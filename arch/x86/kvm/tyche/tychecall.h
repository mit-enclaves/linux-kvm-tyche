#ifndef __KVM_X86_TYCHE_TYCHECALL_H
#define __KVM_X86_TYCHE_TYCHECALL_H

#include <linux/nospec.h>

// Tyche calls interface

int tyche_create_domain(struct file *handle);

int tyche_set_traps(struct file *handle, uint64_t traps);

int tyche_set_cores(struct file *handle, unsigned long long core_map);

#endif
