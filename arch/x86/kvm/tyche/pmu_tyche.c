#include <linux/types.h>
#include <linux/kvm_host.h>
#include "x86.h"
#include "pmu.h"

static bool intel_hw_event_available(struct kvm_pmc *pmc)
{
	return 0;
}

static bool intel_pmc_is_enabled(struct kvm_pmc *pmc)
{
	return 0;
}

static struct kvm_pmc *intel_pmc_idx_to_pmc(struct kvm_pmu *pmu, int pmc_idx)
{
	return NULL;
}

static struct kvm_pmc *intel_rdpmc_ecx_to_pmc(struct kvm_vcpu *vcpu,
					    unsigned int idx, u64 *mask)
{
	return NULL;
}

static struct kvm_pmc *intel_msr_idx_to_pmc(struct kvm_vcpu *vcpu, u32 msr)
{
	return NULL;
}

static bool intel_is_valid_rdpmc_ecx(struct kvm_vcpu *vcpu, unsigned int idx)
{
	return false;
}

static bool intel_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	return false;
}

static int intel_pmu_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return 1;
}

static int intel_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return 1;
}

static void intel_pmu_refresh(struct kvm_vcpu *vcpu)
{
	return;
}

static void intel_pmu_init(struct kvm_vcpu *vcpu)
{
	return;
}

static void intel_pmu_reset(struct kvm_vcpu *vcpu)
{
	return;
}

static void intel_pmu_deliver_pmi(struct kvm_vcpu *vcpu)
{
	return;
}

static void intel_pmu_cleanup(struct kvm_vcpu *vcpu)
{
	return;
}

struct kvm_pmu_ops tyche_pmu_ops __initdata = {
	.hw_event_available = intel_hw_event_available,
	.pmc_is_enabled = intel_pmc_is_enabled,
	.pmc_idx_to_pmc = intel_pmc_idx_to_pmc,
	.rdpmc_ecx_to_pmc = intel_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = intel_msr_idx_to_pmc,
	.is_valid_rdpmc_ecx = intel_is_valid_rdpmc_ecx,
	.is_valid_msr = intel_is_valid_msr,
	.get_msr = intel_pmu_get_msr,
	.set_msr = intel_pmu_set_msr,
	.refresh = intel_pmu_refresh,
	.init = intel_pmu_init,
	.reset = intel_pmu_reset,
	.deliver_pmi = intel_pmu_deliver_pmi,
	.cleanup = intel_pmu_cleanup,
};

