/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVM_PARA_H
#define _UAPI__LINUX_KVM_PARA_H

/*
 * This header file provides a method for making a hypercall to the host
 * Architectures should define:
 * - kvm_hypercall0, kvm_hypercall1...
 * - kvm_arch_para_features
 * - kvm_para_available
 */

/* Return values for hypercalls */
#define KVM_ENOSYS		1000
#define KVM_EFAULT		EFAULT
#define KVM_EINVAL		EINVAL
#define KVM_E2BIG		E2BIG
#define KVM_EPERM		EPERM
#define KVM_EOPNOTSUPP		95

#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2
#define KVM_HC_FEATURES			3
#define KVM_HC_PPC_MAP_MAGIC_PAGE	4
#define KVM_HC_KICK_CPU			5
#define KVM_HC_MIPS_GET_CLOCK_FREQ	6
#define KVM_HC_MIPS_EXIT_VM		7
#define KVM_HC_MIPS_CONSOLE_OUTPUT	8
#define KVM_HC_CLOCK_PAIRING		9
#define KVM_HC_SEND_IPI		10
#define KVM_HC_SCHED_YIELD		11
#define KVM_HC_MAP_GPA_RANGE		12

//@aghosn: Added for Tyche
#define KVM_HC_WRITE_MMIO 13
#define KVM_HC_READ_MMIO 14

/* Call from a confidential TD into the KVM hypercall routine. */
#define TYCHE_CALL_MGMT 25

extern int tyche_turned_confidential;

/* Helper functions to invoke the hypercall mmio. */

#define HC_DO_WRITE_MMIO(addr, val, size) do { \
	asm volatile( \
		"movq %0, %%rdi\n\t" \
		"movq %1, %%rbx\n\t" \
		"movq %2, %%rcx\n\t" \
		"movq %3, %%rdx\n\t" \
		"movq $25, %%rax\n\t" \
		"vmcall\n\t" \
		: \
		: "rm" ((uint64_t) KVM_HC_WRITE_MMIO), "rm" (addr), \
				"rm" ((uint64_t) val), "rm" ((uint64_t)size) \
		: "rdi", "rbx", "rcx", "rdx", "rax", "memory"); \
} while(0);

#define HC_DO_READ_MMIO(addr, dest, size) do { \
	asm volatile( \
		"movq %1, %%rdi\n\t" \
		"movq %2, %%rbx\n\t" \
		"movq %3, %%rcx\n\t" \
		"movq $25, %%rax\n\t" \
		"vmcall\n\t" \
		"movq %%rax, %0\n\t" \
		: "=rm" (dest) \
		: "rm" ((uint64_t) KVM_HC_READ_MMIO), "rm" (addr), "rm" ((uint64_t)size) \
		: "rdi", "rbx", "rcx", "rax", "memory"); \
} while(0);

/*
 * hypercalls use architecture specific
 */
#include <asm/kvm_para.h>

#endif /* _UAPI__LINUX_KVM_PARA_H */
