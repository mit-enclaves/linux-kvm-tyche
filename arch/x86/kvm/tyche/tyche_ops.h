/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TYCHE_OPS_H
#define __KVM_X86_TYCHE_OPS_H

#include <linux/nospec.h>

#include <asm/vmx.h>

#include "../x86.h"

#define SUCCESS (0)
#define FAILURE (-1)

#define TYCHE_KVM_VMX_OPS 14

#define TYCHE_KVM_VMX_READL 0
#define TYCHE_KVM_VMX_WRITEL 1

// A type to pass arguments and receive when calling tyche.
typedef struct vmcall_frame_t {
	// Vmcall id.
	uint64_t vmcall;

	// Arguments.
	uint64_t arg_1;
	uint64_t arg_2;
	uint64_t arg_3;
	uint64_t arg_4;
	uint64_t arg_5;
	uint64_t arg_6;

	// Results.
	uint64_t value_1;
	uint64_t value_2;
	uint64_t value_3;
	uint64_t value_4;
	uint64_t value_5;
	uint64_t value_6;
} vmcall_frame_t;

static __always_inline int tyche_call(vmcall_frame_t *frame)
{
	uint64_t result = FAILURE;
	asm volatile(
		// Setting arguments.
		"movq %7, %%rax\n\t"
		"movq %8, %%rdi\n\t"
		"movq %9, %%rsi\n\n"
		"movq %10, %%rdx\n\t"
		"movq %11, %%rcx\n\t"
		"movq %12, %%r8\n\t"
		"movq %13, %%r9\n\t"
		"vmcall\n\t"
		// Receiving results.
		"movq %%rax, %0\n\t"
		"movq %%rdi, %1\n\t"
		"movq %%rsi, %2\n\t"
		"movq %%rdx, %3\n\t"
		"movq %%rcx, %4\n\t"
		"movq %%r8,  %5\n\t"
		"movq %%r9,  %6\n\t"
		: "=rm"(result), "=rm"(frame->value_1), "=rm"(frame->value_2),
		  "=rm"(frame->value_3), "=rm"(frame->value_4),
		  "=rm"(frame->value_5), "=rm"(frame->value_6)
		: "rm"(frame->vmcall), "rm"(frame->arg_1), "rm"(frame->arg_2),
		  "rm"(frame->arg_3), "rm"(frame->arg_4), "rm"(frame->arg_5),
		  "rm"(frame->arg_6)
		: "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
	return (int)result;
}

/** This part is directly copied from vmx/vmx_ops.h */
static __always_inline void vmcs_check16(unsigned long field)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6001) == 0x2000,
			 "16-bit accessor invalid for 64-bit field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6001) == 0x2001,
			 "16-bit accessor invalid for 64-bit high field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6000) == 0x4000,
			 "16-bit accessor invalid for 32-bit high field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6000) == 0x6000,
			 "16-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_check32(unsigned long field)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field)&0x6000) == 0,
			 "32-bit accessor invalid for 16-bit field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6001) == 0x2000,
			 "32-bit accessor invalid for 64-bit field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6001) == 0x2001,
			 "32-bit accessor invalid for 64-bit high field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6000) == 0x6000,
			 "32-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_check64(unsigned long field)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field)&0x6000) == 0,
			 "64-bit accessor invalid for 16-bit field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6001) == 0x2001,
			 "64-bit accessor invalid for 64-bit high field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6000) == 0x4000,
			 "64-bit accessor invalid for 32-bit field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6000) == 0x6000,
			 "64-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_checkl(unsigned long field)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field)&0x6000) == 0,
			 "Natural width accessor invalid for 16-bit field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6001) == 0x2000,
			 "Natural width accessor invalid for 64-bit field");
	BUILD_BUG_ON_MSG(
		__builtin_constant_p(field) && ((field)&0x6001) == 0x2001,
		"Natural width accessor invalid for 64-bit high field");
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
				 ((field)&0x6000) == 0x4000,
			 "Natural width accessor invalid for 32-bit field");
}

/** Instead of directly issuing vmread, we must call into tyche */
static __always_inline unsigned long __tyche_vmcs_readl(unsigned long field)
{
	vmcall_frame_t frame = {
		.vmcall = TYCHE_KVM_VMX_OPS,
		.arg_1 = TYCHE_KVM_VMX_READL,
		.arg_2 = field,
	};

	if (tyche_call(&frame) != SUCCESS) {
		printk(KERN_ERR "kvm-tyche: tyche_vmcs_readl failed!\n");
	}

	return frame.value_1;
}

static __always_inline u16 tyche_vmcs_read16(unsigned long field)
{
	vmcs_check16(field);
	return __tyche_vmcs_readl(field);
}

static __always_inline u32 tyche_vmcs_read32(unsigned long field)
{
	vmcs_check32(field);
	return __tyche_vmcs_readl(field);
}

static __always_inline u64 tyche_vmcs_read64(unsigned long field)
{
	vmcs_check64(field);
	return __tyche_vmcs_readl(field);
}

static __always_inline unsigned long tyche_vmcs_readl(unsigned long field)
{
	vmcs_checkl(field);
	return __tyche_vmcs_readl(field);
}

static __always_inline void __tyche_vmcs_writel(unsigned long field,
						unsigned long value)
{
	vmcall_frame_t frame = {
		.vmcall = TYCHE_KVM_VMX_OPS,
		.arg_1 = TYCHE_KVM_VMX_WRITEL,
		.arg_2 = field,
		.arg_3 = value,
	};

	if (tyche_call(&frame) != SUCCESS) {
		printk(KERN_ERR "kvm-tyche: tyche_vmcs_writel failed!\n");
	}
}

static __always_inline void tyche_vmcs_write16(unsigned long field, u16 value)
{
	vmcs_check16(field);
	__tyche_vmcs_writel(field, value);
}

static __always_inline void tyche_vmcs_write32(unsigned long field, u32 value)
{
	vmcs_check32(field);
	__tyche_vmcs_writel(field, value);
}

static __always_inline void tyche_vmcs_write64(unsigned long field, u64 value)
{
	vmcs_check64(field);
	__tyche_vmcs_writel(field, value);
}

static __always_inline void tyche_vmcs_writel(unsigned long field,
					      unsigned long value)
{
	vmcs_checkl(field);
	__tyche_vmcs_writel(field, value);
}

#endif /* __KVM_X86_VMX_INSN_H */
