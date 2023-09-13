#ifndef __KVM_X86_TYCHE_H
#define __KVM_X86_TYCHE_H

#include <linux/kvm_host.h>

#include <asm/kvm.h>
#include <asm/vmx.h>
#include <asm/intel_pt.h>
#include <asm/perf_event.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/nospec.h>
#include <linux/spinlock.h>

#include "../kvm_cache_regs.h"
#include "domains.h"

struct vmcs_config {
};
extern struct vmcs_config vmcs_config;

struct kvm_tyche {
	struct kvm kvm;

	// Pointer to the tyche driver domain.
	driver_domain_t *domain;
};

// ——————————————————————————— Segment structures ——————————————————————————— //
typedef struct {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_tyche_segment_field_t;

// ———————————————————————————— Vcpu structures ————————————————————————————— //

typedef enum {
	CS = 0,
	DS = 1,
	ES = 2,
	FS = 3,
	GS = 4,
	SS = 5,
	TR = 6,
	LDTR = 7,
	Seg_End = 8,
} seg_idx_t;

struct vcpu_tyche {
	struct kvm_vcpu vcpu;
	// Registers.
	u64 regs[NR_VCPU_REGS];
	// Segments.
	struct kvm_segment segs[Seg_End];
};

#endif /* __KVM_X86_TYCHE_H */
