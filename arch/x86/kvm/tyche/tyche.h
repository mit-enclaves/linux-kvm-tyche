#ifndef __KVM_X86_TYCHE_H
#define __KVM_X86_TYCHE_H

#include <linux/kvm_host.h>

#include <asm/kvm.h>

#include "tyche_ops.h"

struct kvm_tyche {
	struct kvm kvm;
};


#endif /* __KVM_X86_TYCHE_H */
