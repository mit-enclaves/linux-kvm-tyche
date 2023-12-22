/// This file defines an x86 specific context cache for tyche.
#ifndef __INCLUDE_x86_ARCH_CACHE__
#define __INCLUDE_x86_ARCH_CACHE__

#include <linux/types.h>

#define ARCH_GP_SIZE 15

typedef u64 natural_width;

// General purpose registers.
// Pointing to the KVM ones.
typedef struct __packed arch_gp_t {
	unsigned long regs[ARCH_GP_SIZE];
} arch_gp_t;

// 64-bits values.
typedef struct __packed arch_64_t {
	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;
	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_msr_load_addr;
	u64 tsc_offset;
	u64 virtual_apic_page_addr;
	u64 apic_access_addr;
	u64 posted_intr_desc_addr;
	u64 ept_pointer;
	u64 eoi_exit_bitmap0;
	u64 eoi_exit_bitmap1;
	u64 eoi_exit_bitmap2;
	u64 eoi_exit_bitmap3;
	u64 xss_exit_bitmap;
	u64 guest_physical_address;
	u64 vmcs_link_pointer;
	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_ia32_efer;
	u64 guest_ia32_perf_global_ctrl;
	u64 guest_pdptr0;
	u64 guest_pdptr1;
	u64 guest_pdptr2;
	u64 guest_pdptr3;
	u64 guest_bndcfgs;
	u64 vmread_bitmap;
	u64 vmwrite_bitmap;
	u64 vm_function_control;
	u64 eptp_list_address;
	u64 pml_address;
	u64 encls_exiting_bitmap;
	u64 tsc_multiplier;
} arch_64_t;

#define ARCH_64_SIZE (sizeof(arch_64_t) / sizeof(u64))

// natural width values.
typedef struct __packed arch_nat_t {
	natural_width cr0_guest_host_mask;
	natural_width cr4_guest_host_mask;
	natural_width cr0_read_shadow;
	natural_width cr4_read_shadow;
	natural_width exit_qualification;
	natural_width guest_linear_address;
	natural_width guest_cr0;
	natural_width guest_cr3;
	natural_width guest_cr4;
	natural_width guest_es_base;
	natural_width guest_cs_base;
	natural_width guest_ss_base;
	natural_width guest_ds_base;
	natural_width guest_fs_base;
	natural_width guest_gs_base;
	natural_width guest_ldtr_base;
	natural_width guest_tr_base;
	natural_width guest_gdtr_base;
	natural_width guest_idtr_base;
	natural_width guest_dr7;
	natural_width guest_rsp;
	natural_width guest_rip;
	natural_width guest_rflags;
	natural_width guest_pending_dbg_exceptions;
	natural_width guest_sysenter_esp;
	natural_width guest_sysenter_eip;
} arch_nat_t;

#define ARCH_NAT_SIZE (sizeof(arch_nat_t) / sizeof(natural_width))

// 32-bit values.
typedef struct __packed arch_32_t {
	u32 pin_based_vm_exec_control;
	u32 cpu_based_vm_exec_control;
	u32 exception_bitmap;
	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;
	u32 cr3_target_count;
	u32 vm_exit_controls;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_controls;
	u32 vm_entry_msr_load_count;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_error_code;
	u32 vm_entry_instruction_len;
	u32 tpr_threshold;
	u32 secondary_vm_exec_control;
	u32 vm_instruction_error;
	u32 vm_exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instruction_len;
	u32 vmx_instruction_info;
	u32 guest_es_limit;
	u32 guest_cs_limit;
	u32 guest_ss_limit;
	u32 guest_ds_limit;
	u32 guest_fs_limit;
	u32 guest_gs_limit;
	u32 guest_ldtr_limit;
	u32 guest_tr_limit;
	u32 guest_gdtr_limit;
	u32 guest_idtr_limit;
	u32 guest_es_ar_bytes;
	u32 guest_cs_ar_bytes;
	u32 guest_ss_ar_bytes;
	u32 guest_ds_ar_bytes;
	u32 guest_fs_ar_bytes;
	u32 guest_gs_ar_bytes;
	u32 guest_ldtr_ar_bytes;
	u32 guest_tr_ar_bytes;
	u32 guest_interruptibility_info;
	u32 guest_activity_state;
	u32 guest_sysenter_cs;
	u32 vmx_preemption_timer_value;
} arch_32_t;

#define ARCH_32_SIZE (sizeof(arch_32_t) / sizeof(u32))

// 16-bit values.
typedef struct __packed arch_16_t {
	u16 virtual_processor_id;
	u16 posted_intr_nv;
	u16 guest_es_selector;
	u16 guest_cs_selector;
	u16 guest_ss_selector;
	u16 guest_ds_selector;
	u16 guest_fs_selector;
	u16 guest_gs_selector;
	u16 guest_ldtr_selector;
	u16 guest_tr_selector;
	u16 guest_intr_status;
	u16 guest_pml_index;
} arch_16_t;

#define ARCH_16_SIZE (sizeof(arch_16_t) / sizeof(u16))

/// Caches the values we read from tyche.
/// This is heavily inspired (stolen) from kvm vmcs12.h
typedef struct __packed arch_bitmap_t {
	/// value was loaded from tyche.
	u64 read;
	/// value was written and needs to be sent to tyche.
	u64 written;
} arch_bitmap_t;

typedef struct __packed arch_cache_t {
	/// General-purpose registers.
	arch_bitmap_t bits_gp;
	arch_gp_t cache_gp;

	/// 64-bit values.
	arch_bitmap_t bits_64;
	arch_64_t cache_64;

	// Natural width values.
	arch_bitmap_t bits_nat;
	arch_nat_t cache_nat;

	// 32-bits values.
	arch_bitmap_t bits_32;
	arch_32_t cache_32;

	// 16-bits values.
	arch_bitmap_t bits_16;
	arch_16_t cache_16;
} arch_cache_t;

// —————————————————————————— Functions we expose ——————————————————————————— //

/// Check if a value is in the cache.
int cache_is_updated(arch_cache_t *cache, unsigned long field);

/// Attempts to read a value from the cache into result (regardless of its size).
/// Returns -1 if cache is null, result is null, field is invalid, or value is not stored.
/// Returns 0 on success.
int cache_read_any(arch_cache_t *cache, unsigned long field, u64 *result);

/// Write the value to the right field.
/// Returns -1 if cache is null or field is invalid.
/// Return 0 on success.
int cache_write_any(arch_cache_t *cache, unsigned long field, u64 field_value);

/// Similar to write, does not mark the value as written though.
int cache_set_any(arch_cache_t *cache, unsigned long filed, u64 field_value);

/// Update the gp cache.
int cache_update_gp(arch_cache_t *cache, unsigned long *regs);

/// Counts how many dirty values are in the cache.
unsigned int cache_dirty_count(arch_cache_t *cache);

/// Collects all dirty values with their fields.
int cache_collect_dirties(arch_cache_t *cache, u64 *values, u64 *fields,
			  int capacity);

/// Resets the written bits, read tells whether to reset read bitmap.
void cache_clear(arch_cache_t *cache, int read);

#endif
