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

#include "capabilities.h"
#include "../kvm_cache_regs.h"
// #include "posted_intr.h"
#include "vmcs.h"
#include "tyche_ops.h"
#include "../cpuid.h"
// #include "run_flags.h"

#define MAX_NR_USER_RETURN_MSRS 7
#define MAX_NR_LOADSTORE_MSRS 8

struct tyche_msrs {
	unsigned int nr;
	struct vmx_msr_entry val[MAX_NR_LOADSTORE_MSRS];
};

struct tyche_uret_msr {
	bool load_into_hardware;
	u64 data;
	u64 mask;
};

enum segment_cache_field {
	SEG_FIELD_SEL = 0,
	SEG_FIELD_BASE = 1,
	SEG_FIELD_LIMIT = 2,
	SEG_FIELD_AR = 3,

	SEG_FIELD_NR = 4
};

#define RTIT_ADDR_RANGE 4

struct pt_ctx {
	u64 ctl;
	u64 status;
	u64 output_base;
	u64 output_mask;
	u64 cr3_match;
	u64 addr_a[RTIT_ADDR_RANGE];
	u64 addr_b[RTIT_ADDR_RANGE];
};

struct pt_desc {
	u64 ctl_bitmask;
	u32 num_address_ranges;
	u32 caps[PT_CPUID_REGS_NUM * PT_CPUID_LEAVES];
	struct pt_ctx host;
	struct pt_ctx guest;
};

union vmx_exit_reason {
	struct {
		u32 basic : 16;
		u32 reserved16 : 1;
		u32 reserved17 : 1;
		u32 reserved18 : 1;
		u32 reserved19 : 1;
		u32 reserved20 : 1;
		u32 reserved21 : 1;
		u32 reserved22 : 1;
		u32 reserved23 : 1;
		u32 reserved24 : 1;
		u32 reserved25 : 1;
		u32 bus_lock_detected : 1;
		u32 enclave_mode : 1;
		u32 smi_pending_mtf : 1;
		u32 smi_from_vmx_root : 1;
		u32 reserved30 : 1;
		u32 failed_vmentry : 1;
	};
	u32 full;
};

struct lbr_desc {
	/* Basic info about guest LBR records. */
	struct x86_pmu_lbr records;

	/*
	 * Emulate LBR feature via passthrough LBR registers when the
	 * per-vcpu guest LBR event is scheduled on the current pcpu.
	 *
	 * The records may be inaccurate if the host reclaims the LBR.
	 */
	struct perf_event *event;

	/* True if LBRs are marked as not intercepted in the MSR bitmap */
	bool msr_passthrough;
};

struct vcpu_tyche {
	struct kvm_vcpu vcpu;
	u8 fail;
	u8 x2apic_msr_bitmap_mode;

	/*
	 * If true, host state has been stored in vmx->loaded_vmcs for
	 * the CPU registers that only need to be switched when transitioning
	 * to/from the kernel, and the registers have been loaded with guest
	 * values.  If false, host state is loaded in the CPU registers
	 * and vmx->loaded_vmcs->host_state is invalid.
	 */
	bool guest_state_loaded;

	unsigned long exit_qualification;
	u32 exit_intr_info;
	u32 idt_vectoring_info;
	ulong rflags;

	/*
	 * User return MSRs are always emulated when enabled in the guest, but
	 * only loaded into hardware when necessary, e.g. SYSCALL #UDs outside
	 * of 64-bit mode or if EFER.SCE=1, thus the SYSCALL MSRs don't need to
	 * be loaded into hardware if those conditions aren't met.
	 */
	struct tyche_uret_msr guest_uret_msrs[MAX_NR_USER_RETURN_MSRS];
	bool guest_uret_msrs_loaded;
#ifdef CONFIG_X86_64
	u64 msr_host_kernel_gs_base;
	u64 msr_guest_kernel_gs_base;
#endif

	u64 spec_ctrl;
	u32 msr_ia32_umwait_control;

	/*
	 * loaded_vmcs points to the VMCS currently used in this vcpu. For a
	 * non-nested (L1) guest, it always points to vmcs01. For a nested
	 * guest (L2), it points to a different VMCS.
	 */
	struct loaded_vmcs vmcs01;
	struct loaded_vmcs *loaded_vmcs;

	struct msr_autoload {
		struct tyche_msrs guest;
		struct tyche_msrs host;
	} msr_autoload;

	struct msr_autostore {
		struct tyche_msrs guest;
	} msr_autostore;

	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	int vpid;
	bool emulation_required;

	union vmx_exit_reason exit_reason;
#if 0
	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Used if this vCPU is waiting for PI notification wakeup. */
	struct list_head pi_wakeup_list;

	/* Support for a guest hypervisor (nested VMX) */
	struct nested_vmx nested;
#endif
	/* Dynamic PLE window. */
	unsigned int ple_window;
	bool ple_window_dirty;

	bool req_immediate_exit;

	/* Support for PML */
#define PML_ENTITY_NUM 512
	struct page *pml_pg;

	/* apic deadline value in host tsc */
	u64 hv_deadline_tsc;

	unsigned long host_debugctlmsr;

	/*
	 * Only bits masked by msr_ia32_feature_control_valid_bits can be set in
	 * msr_ia32_feature_control. FEAT_CTL_LOCKED is always included
	 * in msr_ia32_feature_control_valid_bits.
	 */
	u64 msr_ia32_feature_control;
	u64 msr_ia32_feature_control_valid_bits;
	/* SGX Launch Control public key hash */
	u64 msr_ia32_sgxlepubkeyhash[4];
	u64 msr_ia32_mcu_opt_ctrl;
	bool disable_fb_clear;

	struct pt_desc pt_desc;
	struct lbr_desc lbr_desc;

	/* Save desired MSR intercept (read: pass-through) state */
#define MAX_POSSIBLE_PASSTHROUGH_MSRS 16
	struct {
		DECLARE_BITMAP(read, MAX_POSSIBLE_PASSTHROUGH_MSRS);
		DECLARE_BITMAP(write, MAX_POSSIBLE_PASSTHROUGH_MSRS);
	} shadow_msr_intercept;
};

struct kvm_tyche {
	struct kvm kvm;
};

bool nested_vmx_allowed(struct kvm_vcpu *vcpu);

#define __KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS				\
	(VM_ENTRY_LOAD_DEBUG_CONTROLS)
#define KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS			        \
	(__KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS |			        \
	 VM_ENTRY_IA32E_MODE)
#define KVM_OPTIONAL_VMX_VM_ENTRY_CONTROLS				\
	(VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |				\
	 VM_ENTRY_LOAD_IA32_PAT |					\
	 VM_ENTRY_LOAD_IA32_EFER |					\
	 VM_ENTRY_LOAD_BNDCFGS |					\
	 VM_ENTRY_PT_CONCEAL_PIP |					\
	 VM_ENTRY_LOAD_IA32_RTIT_CTL)

#define __KVM_REQUIRED_VMX_VM_EXIT_CONTROLS				\
	(VM_EXIT_SAVE_DEBUG_CONTROLS |					\
	 VM_EXIT_ACK_INTR_ON_EXIT)
#define KVM_REQUIRED_VMX_VM_EXIT_CONTROLS			        \
	(__KVM_REQUIRED_VMX_VM_EXIT_CONTROLS |			        \
	 VM_EXIT_HOST_ADDR_SPACE_SIZE)

#define KVM_OPTIONAL_VMX_VM_EXIT_CONTROLS				\
	      (VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL |			\
	       VM_EXIT_SAVE_IA32_PAT |					\
	       VM_EXIT_LOAD_IA32_PAT |					\
	       VM_EXIT_SAVE_IA32_EFER |					\
	       VM_EXIT_SAVE_VMX_PREEMPTION_TIMER |			\
	       VM_EXIT_LOAD_IA32_EFER |					\
	       VM_EXIT_CLEAR_BNDCFGS |					\
	       VM_EXIT_PT_CONCEAL_PIP |					\
	       VM_EXIT_CLEAR_IA32_RTIT_CTL)

#define KVM_REQUIRED_VMX_PIN_BASED_VM_EXEC_CONTROL			\
	(PIN_BASED_EXT_INTR_MASK |					\
	 PIN_BASED_NMI_EXITING)
#define KVM_OPTIONAL_VMX_PIN_BASED_VM_EXEC_CONTROL			\
	(PIN_BASED_VIRTUAL_NMIS |					\
	 PIN_BASED_POSTED_INTR |					\
	 PIN_BASED_VMX_PREEMPTION_TIMER)

#define __KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL			\
	(CPU_BASED_HLT_EXITING |					\
	 CPU_BASED_CR3_LOAD_EXITING |					\
	 CPU_BASED_CR3_STORE_EXITING |					\
	 CPU_BASED_UNCOND_IO_EXITING |					\
	 CPU_BASED_MOV_DR_EXITING |					\
	 CPU_BASED_USE_TSC_OFFSETTING |					\
	 CPU_BASED_MWAIT_EXITING |					\
	 CPU_BASED_MONITOR_EXITING |					\
	 CPU_BASED_INVLPG_EXITING |					\
	 CPU_BASED_RDPMC_EXITING |					\
	 CPU_BASED_INTR_WINDOW_EXITING)

#define KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL		        \
	(__KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL |		        \
	 CPU_BASED_CR8_LOAD_EXITING |				        \
	 CPU_BASED_CR8_STORE_EXITING)

#define KVM_OPTIONAL_VMX_CPU_BASED_VM_EXEC_CONTROL			\
	(CPU_BASED_RDTSC_EXITING |					\
	 CPU_BASED_TPR_SHADOW |						\
	 CPU_BASED_USE_IO_BITMAPS |					\
	 CPU_BASED_MONITOR_TRAP_FLAG |					\
	 CPU_BASED_USE_MSR_BITMAPS |					\
	 CPU_BASED_NMI_WINDOW_EXITING |					\
	 CPU_BASED_PAUSE_EXITING |					\
	 CPU_BASED_ACTIVATE_SECONDARY_CONTROLS |			\
	 CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)

#define KVM_REQUIRED_VMX_SECONDARY_VM_EXEC_CONTROL 0
#define KVM_OPTIONAL_VMX_SECONDARY_VM_EXEC_CONTROL			\
	(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |			\
	 SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |			\
	 SECONDARY_EXEC_WBINVD_EXITING |				\
	 SECONDARY_EXEC_ENABLE_VPID |					\
	 SECONDARY_EXEC_ENABLE_EPT |					\
	 SECONDARY_EXEC_UNRESTRICTED_GUEST |				\
	 SECONDARY_EXEC_PAUSE_LOOP_EXITING |				\
	 SECONDARY_EXEC_DESC |						\
	 SECONDARY_EXEC_ENABLE_RDTSCP |					\
	 SECONDARY_EXEC_ENABLE_INVPCID |				\
	 SECONDARY_EXEC_APIC_REGISTER_VIRT |				\
	 SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |				\
	 SECONDARY_EXEC_SHADOW_VMCS |					\
	 SECONDARY_EXEC_XSAVES |					\
	 SECONDARY_EXEC_RDSEED_EXITING |				\
	 SECONDARY_EXEC_RDRAND_EXITING |				\
	 SECONDARY_EXEC_ENABLE_PML |					\
	 SECONDARY_EXEC_TSC_SCALING |					\
	 SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE |				\
	 SECONDARY_EXEC_PT_USE_GPA |					\
	 SECONDARY_EXEC_PT_CONCEAL_VMX |				\
	 SECONDARY_EXEC_ENABLE_VMFUNC |					\
	 SECONDARY_EXEC_BUS_LOCK_DETECTION |				\
	 SECONDARY_EXEC_NOTIFY_VM_EXITING |				\
	 SECONDARY_EXEC_ENCLS_EXITING)

#define KVM_REQUIRED_VMX_TERTIARY_VM_EXEC_CONTROL 0
#define KVM_OPTIONAL_VMX_TERTIARY_VM_EXEC_CONTROL			\
	(TERTIARY_EXEC_IPI_VIRT)

#define BUILD_CONTROLS_SHADOW(lname, uname, bits)						\
static inline void lname##_controls_set(struct vcpu_tyche *tyche, u##bits val)			\
{												\
	if (tyche->loaded_vmcs->controls_shadow.lname != val) {					\
		tyche_vmcs_write##bits(uname, val);							\
		tyche->loaded_vmcs->controls_shadow.lname = val;					\
	}											\
}												\
static inline u##bits __##lname##_controls_get(struct loaded_vmcs *vmcs)			\
{												\
	return vmcs->controls_shadow.lname;							\
}												\
static inline u##bits lname##_controls_get(struct vcpu_tyche *tyche)				\
{												\
	return __##lname##_controls_get(tyche->loaded_vmcs);					\
}												\
static __always_inline void lname##_controls_setbit(struct vcpu_tyche *tyche, u##bits val)		\
{												\
	BUILD_BUG_ON(!(val & (KVM_REQUIRED_VMX_##uname | KVM_OPTIONAL_VMX_##uname)));		\
	lname##_controls_set(tyche, lname##_controls_get(tyche) | val);				\
}												\
static __always_inline void lname##_controls_clearbit(struct vcpu_tyche *tyche, u##bits val)	\
{												\
	BUILD_BUG_ON(!(val & (KVM_REQUIRED_VMX_##uname | KVM_OPTIONAL_VMX_##uname)));		\
	lname##_controls_set(tyche, lname##_controls_get(tyche) & ~val);				\
}
BUILD_CONTROLS_SHADOW(vm_entry, VM_ENTRY_CONTROLS, 32)
BUILD_CONTROLS_SHADOW(vm_exit, VM_EXIT_CONTROLS, 32)
BUILD_CONTROLS_SHADOW(pin, PIN_BASED_VM_EXEC_CONTROL, 32)
BUILD_CONTROLS_SHADOW(exec, CPU_BASED_VM_EXEC_CONTROL, 32)
BUILD_CONTROLS_SHADOW(secondary_exec, SECONDARY_VM_EXEC_CONTROL, 32)
BUILD_CONTROLS_SHADOW(tertiary_exec, TERTIARY_VM_EXEC_CONTROL, 64)

static inline bool vmx_has_waitpkg(struct vcpu_tyche *vmx)
{
	return secondary_exec_controls_get(vmx) &
		SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE;
}

static __always_inline struct kvm_tyche *to_kvm_tyche(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tyche, kvm);
}

static __always_inline struct vcpu_tyche *to_tyche(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tyche, vcpu);
}

#endif /* __KVM_X86_TYCHE_H */
