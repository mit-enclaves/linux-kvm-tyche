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

struct vcpu_tyche {
	struct kvm_vcpu vcpu;
};

#endif /* __KVM_X86_TYCHE_H */
