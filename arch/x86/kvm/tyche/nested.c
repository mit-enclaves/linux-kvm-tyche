#include "nested.h"

#include <asm/msr-index.h>

static inline u64 vmx_control_msr(u32 low, u32 high)
{
	return low | ((u64)high << 32);
}

static bool is_bitwise_subset(u64 superset, u64 subset, u64 mask)
{
	superset &= mask;
	subset &= mask;

	return (superset | subset) == superset;
}


static int vmx_restore_vmx_basic(struct vcpu_tyche *vmx, u64 data)
{
	const u64 feature_and_reserved =
		/* feature (except bit 48; see below) */
		BIT_ULL(49) | BIT_ULL(54) | BIT_ULL(55) |
		/* reserved */
		BIT_ULL(31) | GENMASK_ULL(47, 45) | GENMASK_ULL(63, 56);
	u64 vmx_basic = vmcs_config.nested.basic;

	if (!is_bitwise_subset(vmx_basic, data, feature_and_reserved))
		return -EINVAL;

	/*
	 * KVM does not emulate a version of VMX that constrains physical
	 * addresses of VMX structures (e.g. VMCS) to 32-bits.
	 */
	if (data & BIT_ULL(48))
		return -EINVAL;

	if (vmx_basic_vmcs_revision_id(vmx_basic) !=
	    vmx_basic_vmcs_revision_id(data))
		return -EINVAL;

	if (vmx_basic_vmcs_size(vmx_basic) > vmx_basic_vmcs_size(data))
		return -EINVAL;

	vmx->nested.msrs.basic = data;
	return 0;
}

static u64 *vmx_get_fixed0_msr(struct nested_vmx_msrs *msrs, u32 msr_index)
{
	switch (msr_index) {
	case MSR_IA32_VMX_CR0_FIXED0:
		return &msrs->cr0_fixed0;
	case MSR_IA32_VMX_CR4_FIXED0:
		return &msrs->cr4_fixed0;
	default:
		BUG();
	}
}

static int vmx_restore_fixed0_msr(struct vcpu_tyche *vmx, u32 msr_index, u64 data)
{
	const u64 *msr = vmx_get_fixed0_msr(&vmcs_config.nested, msr_index);

	/*
	 * 1 bits (which indicates bits which "must-be-1" during VMX operation)
	 * must be 1 in the restored value.
	 */
	if (!is_bitwise_subset(data, *msr, -1ULL))
		return -EINVAL;

	*vmx_get_fixed0_msr(&vmx->nested.msrs, msr_index) = data;
	return 0;
}

static void vmx_get_control_msr(struct nested_vmx_msrs *msrs, u32 msr_index,
				u32 **low, u32 **high)
{
	switch (msr_index) {
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
		*low = &msrs->pinbased_ctls_low;
		*high = &msrs->pinbased_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
		*low = &msrs->procbased_ctls_low;
		*high = &msrs->procbased_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
		*low = &msrs->exit_ctls_low;
		*high = &msrs->exit_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
		*low = &msrs->entry_ctls_low;
		*high = &msrs->entry_ctls_high;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*low = &msrs->secondary_ctls_low;
		*high = &msrs->secondary_ctls_high;
		break;
	default:
		BUG();
	}
}

static int
vmx_restore_control_msr(struct vcpu_tyche *vmx, u32 msr_index, u64 data)
{
	u32 *lowp, *highp;
	u64 supported;

	vmx_get_control_msr(&vmcs_config.nested, msr_index, &lowp, &highp);

	supported = vmx_control_msr(*lowp, *highp);

	/* Check must-be-1 bits are still 1. */
	if (!is_bitwise_subset(data, supported, GENMASK_ULL(31, 0)))
		return -EINVAL;

	/* Check must-be-0 bits are still 0. */
	if (!is_bitwise_subset(supported, data, GENMASK_ULL(63, 32)))
		return -EINVAL;

	vmx_get_control_msr(&vmx->nested.msrs, msr_index, &lowp, &highp);
	*lowp = data;
	*highp = data >> 32;
	return 0;
}

static int vmx_restore_vmx_misc(struct vcpu_tyche *vmx, u64 data)
{
	const u64 feature_and_reserved_bits =
		/* feature */
		BIT_ULL(5) | GENMASK_ULL(8, 6) | BIT_ULL(14) | BIT_ULL(15) |
		BIT_ULL(28) | BIT_ULL(29) | BIT_ULL(30) |
		/* reserved */
		GENMASK_ULL(13, 9) | BIT_ULL(31);
	u64 vmx_misc = vmx_control_msr(vmcs_config.nested.misc_low,
				       vmcs_config.nested.misc_high);

	if (!is_bitwise_subset(vmx_misc, data, feature_and_reserved_bits))
		return -EINVAL;

	if ((vmx->nested.msrs.pinbased_ctls_high &
	     PIN_BASED_VMX_PREEMPTION_TIMER) &&
	    vmx_misc_preemption_timer_rate(data) !=
	    vmx_misc_preemption_timer_rate(vmx_misc))
		return -EINVAL;

	if (vmx_misc_cr3_count(data) > vmx_misc_cr3_count(vmx_misc))
		return -EINVAL;

	if (vmx_misc_max_msr(data) > vmx_misc_max_msr(vmx_misc))
		return -EINVAL;

	if (vmx_misc_mseg_revid(data) != vmx_misc_mseg_revid(vmx_misc))
		return -EINVAL;

	vmx->nested.msrs.misc_low = data;
	vmx->nested.msrs.misc_high = data >> 32;

	return 0;
}

static int vmx_restore_vmx_ept_vpid_cap(struct vcpu_tyche *vmx, u64 data)
{
	u64 vmx_ept_vpid_cap = vmx_control_msr(vmcs_config.nested.ept_caps,
					       vmcs_config.nested.vpid_caps);

	/* Every bit is either reserved or a feature bit. */
	if (!is_bitwise_subset(vmx_ept_vpid_cap, data, -1ULL))
		return -EINVAL;

	vmx->nested.msrs.ept_caps = data;
	vmx->nested.msrs.vpid_caps = data >> 32;
	return 0;
}

/*
 * Called when userspace is restoring VMX MSRs.
 *
 * Returns 0 on success, non-0 otherwise.
 */
int tyche_set_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data)
{
	struct vcpu_tyche *vmx = to_tyche(vcpu);

	/*
	 * Don't allow changes to the VMX capability MSRs while the vCPU
	 * is in VMX operation.
	 */
	if (vmx->nested.vmxon)
		return -EBUSY;

	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		return vmx_restore_vmx_basic(vmx, data);
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		/*
		 * The "non-true" VMX capability MSRs are generated from the
		 * "true" MSRs, so we do not support restoring them directly.
		 *
		 * If userspace wants to emulate VMX_BASIC[55]=0, userspace
		 * should restore the "true" MSRs with the must-be-1 bits
		 * set according to the SDM Vol 3. A.2 "RESERVED CONTROLS AND
		 * DEFAULT SETTINGS".
		 */
		return -EINVAL;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		return vmx_restore_control_msr(vmx, msr_index, data);
	case MSR_IA32_VMX_MISC:
		return vmx_restore_vmx_misc(vmx, data);
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED0:
		return vmx_restore_fixed0_msr(vmx, msr_index, data);
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED1:
		/*
		 * These MSRs are generated based on the vCPU's CPUID, so we
		 * do not support restoring them directly.
		 */
		return -EINVAL;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		return vmx_restore_vmx_ept_vpid_cap(vmx, data);
	case MSR_IA32_VMX_VMCS_ENUM:
		vmx->nested.msrs.vmcs_enum = data;
		return 0;
	case MSR_IA32_VMX_VMFUNC:
		if (data & ~vmcs_config.nested.vmfunc_controls)
			return -EINVAL;
		vmx->nested.msrs.vmfunc_controls = data;
		return 0;
	default:
		/*
		 * The rest of the VMX capability MSRs do not support restore.
		 */
		return -EINVAL;
	}
}

/* Returns 0 on success, non-0 otherwise. */
int tyche_get_vmx_msr(struct nested_vmx_msrs *msrs, u32 msr_index, u64 *pdata)
{
	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		*pdata = msrs->basic;
		break;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_PINBASED_CTLS:
		*pdata = vmx_control_msr(
			msrs->pinbased_ctls_low,
			msrs->pinbased_ctls_high);
		if (msr_index == MSR_IA32_VMX_PINBASED_CTLS)
			*pdata |= PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
		*pdata = vmx_control_msr(
			msrs->procbased_ctls_low,
			msrs->procbased_ctls_high);
		if (msr_index == MSR_IA32_VMX_PROCBASED_CTLS)
			*pdata |= CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
		*pdata = vmx_control_msr(
			msrs->exit_ctls_low,
			msrs->exit_ctls_high);
		if (msr_index == MSR_IA32_VMX_EXIT_CTLS)
			*pdata |= VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		*pdata = vmx_control_msr(
			msrs->entry_ctls_low,
			msrs->entry_ctls_high);
		if (msr_index == MSR_IA32_VMX_ENTRY_CTLS)
			*pdata |= VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_MISC:
		*pdata = vmx_control_msr(
			msrs->misc_low,
			msrs->misc_high);
		break;
	case MSR_IA32_VMX_CR0_FIXED0:
		*pdata = msrs->cr0_fixed0;
		break;
	case MSR_IA32_VMX_CR0_FIXED1:
		*pdata = msrs->cr0_fixed1;
		break;
	case MSR_IA32_VMX_CR4_FIXED0:
		*pdata = msrs->cr4_fixed0;
		break;
	case MSR_IA32_VMX_CR4_FIXED1:
		*pdata = msrs->cr4_fixed1;
		break;
	case MSR_IA32_VMX_VMCS_ENUM:
		*pdata = msrs->vmcs_enum;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*pdata = vmx_control_msr(
			msrs->secondary_ctls_low,
			msrs->secondary_ctls_high);
		break;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		*pdata = msrs->ept_caps |
			((u64)msrs->vpid_caps << 32);
		break;
	case MSR_IA32_VMX_VMFUNC:
		*pdata = msrs->vmfunc_controls;
		break;
	default:
		return 1;
	}

	return 0;
}

