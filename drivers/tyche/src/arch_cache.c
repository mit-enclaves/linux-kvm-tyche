#include "arch_cache.h"
#include "common.h"
#include "common_log.h"
#include "linux/stddef.h"
#include "tyche_register_map.h"

#define WARN_ON_ONCE(cond) {};

#include <asm/vmx.h>
#include<linux/string.h>

// Maps vmcs fields width.
enum cache_width {
  WIDTH_16 = 0,
  WIDTH_64 = 1,
  WIDTH_32 = 2,
  WIDTH_NAT = 3,
  WIDTH_GP = 4,
};

const unsigned int arch_gp_names[ARCH_GP_SIZE] = {
  REG_GP_RAX,
  REG_GP_RBX,
  REG_GP_RCX,
  REG_GP_RDX,
  REG_GP_RBP,
  REG_GP_RSI,
  REG_GP_RDI,
  REG_GP_R8,
  REG_GP_R9,
  REG_GP_R10,
  REG_GP_R11,
  REG_GP_R12,
  REG_GP_R13,
  REG_GP_R14,
  REG_GP_R15,
};

const unsigned int arch_64_names[ARCH_64_SIZE] = {
	IO_BITMAP_A,
	IO_BITMAP_B,
	MSR_BITMAP,
	VM_EXIT_MSR_STORE_ADDR,
	VM_EXIT_MSR_LOAD_ADDR,
	VM_ENTRY_MSR_LOAD_ADDR,
	TSC_OFFSET,
	VIRTUAL_APIC_PAGE_ADDR,
	APIC_ACCESS_ADDR,
	POSTED_INTR_DESC_ADDR,
	EPT_POINTER,
	EOI_EXIT_BITMAP0,
	EOI_EXIT_BITMAP1,
	EOI_EXIT_BITMAP2,
	EOI_EXIT_BITMAP3,
	XSS_EXIT_BITMAP,
	GUEST_PHYSICAL_ADDRESS,
	VMCS_LINK_POINTER,
	GUEST_IA32_DEBUGCTL,
	GUEST_IA32_PAT,
	GUEST_IA32_EFER,
	GUEST_IA32_PERF_GLOBAL_CTRL,
	GUEST_PDPTR0,
	GUEST_PDPTR1,
	GUEST_PDPTR2,
	GUEST_PDPTR3,
	GUEST_BNDCFGS,
	VMREAD_BITMAP,
	VMWRITE_BITMAP,
	VM_FUNCTION_CONTROL,
	EPTP_LIST_ADDRESS,
	PML_ADDRESS,
	ENCLS_EXITING_BITMAP,
	TSC_MULTIPLIER,
};

const unsigned int arch_nat_names[ARCH_NAT_SIZE] = {
	CR0_GUEST_HOST_MASK,
	CR4_GUEST_HOST_MASK,
	CR0_READ_SHADOW,
	CR4_READ_SHADOW,
	EXIT_QUALIFICATION,
	GUEST_LINEAR_ADDRESS,
	GUEST_CR0,
	GUEST_CR3,
	GUEST_CR4,
	GUEST_ES_BASE,
	GUEST_CS_BASE,
	GUEST_SS_BASE,
	GUEST_DS_BASE,
	GUEST_FS_BASE,
	GUEST_GS_BASE,
	GUEST_LDTR_BASE,
	GUEST_TR_BASE,
	GUEST_GDTR_BASE,
	GUEST_IDTR_BASE,
	GUEST_DR7,
	GUEST_RSP,
	GUEST_RIP,
	GUEST_RFLAGS,
	GUEST_PENDING_DBG_EXCEPTIONS,
	GUEST_SYSENTER_ESP,
	GUEST_SYSENTER_EIP,
};

const unsigned int arch_32_names[ARCH_32_SIZE] = {
	PIN_BASED_VM_EXEC_CONTROL,
	CPU_BASED_VM_EXEC_CONTROL,
	EXCEPTION_BITMAP,
	PAGE_FAULT_ERROR_CODE_MASK,
	PAGE_FAULT_ERROR_CODE_MATCH,
	CR3_TARGET_COUNT,
	VM_EXIT_CONTROLS,
	VM_EXIT_MSR_STORE_COUNT,
	VM_EXIT_MSR_LOAD_COUNT,
	VM_ENTRY_CONTROLS,
	VM_ENTRY_MSR_LOAD_COUNT,
	VM_ENTRY_INTR_INFO_FIELD,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	VM_ENTRY_INSTRUCTION_LEN,
	TPR_THRESHOLD,
	SECONDARY_VM_EXEC_CONTROL,
	VM_INSTRUCTION_ERROR,
	VM_EXIT_REASON,
	VM_EXIT_INTR_INFO,
	VM_EXIT_INTR_ERROR_CODE,
	IDT_VECTORING_INFO_FIELD,
	IDT_VECTORING_ERROR_CODE,
	VM_EXIT_INSTRUCTION_LEN,
	VMX_INSTRUCTION_INFO,
	GUEST_ES_LIMIT,
	GUEST_CS_LIMIT,
	GUEST_SS_LIMIT,
	GUEST_DS_LIMIT,
	GUEST_FS_LIMIT,
	GUEST_GS_LIMIT,
	GUEST_LDTR_LIMIT,
	GUEST_TR_LIMIT,
	GUEST_GDTR_LIMIT,
	GUEST_IDTR_LIMIT,
	GUEST_ES_AR_BYTES,
	GUEST_CS_AR_BYTES,
	GUEST_SS_AR_BYTES,
	GUEST_DS_AR_BYTES,
	GUEST_FS_AR_BYTES,
	GUEST_GS_AR_BYTES,
	GUEST_LDTR_AR_BYTES,
	GUEST_TR_AR_BYTES,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_ACTIVITY_STATE,
	GUEST_SYSENTER_CS,
	VMX_PREEMPTION_TIMER_VALUE,
};

const unsigned int arch_16_names[ARCH_16_SIZE] = {
	VIRTUAL_PROCESSOR_ID,
	POSTED_INTR_NV,
	GUEST_ES_SELECTOR,
	GUEST_CS_SELECTOR,
	GUEST_SS_SELECTOR,
	GUEST_DS_SELECTOR,
	GUEST_FS_SELECTOR,
	GUEST_GS_SELECTOR,
	GUEST_LDTR_SELECTOR,
	GUEST_TR_SELECTOR,
	GUEST_INTR_STATUS,
	GUEST_PML_INDEX,
};

#define VALID_MASK ((unsigned short) (1 << 15)) 
#define ROL16(val, n) ((u16)(((u16)(val) << (n)) | ((u16)(val) >> (16 - (n)))))
#define FIELDNAT(number, field) [ROL16(number, 6)] = VALID_MASK | offsetof(arch_nat_t, field)
#define FIELD64(number, field) [ROL16(number, 6)] = VALID_MASK | offsetof(arch_64_t, field) 
#define FIELD32(number, field) [ROL16(number, 6)] = VALID_MASK | offsetof(arch_32_t, field)
#define FIELD16(number, field) [ROL16(number, 6)] = VALID_MASK | offsetof(arch_16_t, field)

#define OFFSET_GP(number) ((number - REG_GP_RAX)/2)
#define FIELD_GP(number) [OFFSET_GP(number)] = VALID_MASK | (OFFSET_GP(number) * sizeof(unsigned long))

const unsigned short index_map[] = {
	FIELD16(VIRTUAL_PROCESSOR_ID, virtual_processor_id),
	FIELD16(POSTED_INTR_NV, posted_intr_nv),
	FIELD16(GUEST_ES_SELECTOR, guest_es_selector),
	FIELD16(GUEST_CS_SELECTOR, guest_cs_selector),
	FIELD16(GUEST_SS_SELECTOR, guest_ss_selector),
	FIELD16(GUEST_DS_SELECTOR, guest_ds_selector),
	FIELD16(GUEST_FS_SELECTOR, guest_fs_selector),
	FIELD16(GUEST_GS_SELECTOR, guest_gs_selector),
	FIELD16(GUEST_LDTR_SELECTOR, guest_ldtr_selector),
	FIELD16(GUEST_TR_SELECTOR, guest_tr_selector),
	FIELD16(GUEST_INTR_STATUS, guest_intr_status),
	FIELD16(GUEST_PML_INDEX, guest_pml_index),
	FIELD64(IO_BITMAP_A, io_bitmap_a),
	FIELD64(IO_BITMAP_B, io_bitmap_b),
	FIELD64(MSR_BITMAP, msr_bitmap),
	FIELD64(VM_EXIT_MSR_STORE_ADDR, vm_exit_msr_store_addr),
	FIELD64(VM_EXIT_MSR_LOAD_ADDR, vm_exit_msr_load_addr),
	FIELD64(VM_ENTRY_MSR_LOAD_ADDR, vm_entry_msr_load_addr),
	FIELD64(PML_ADDRESS, pml_address),
	FIELD64(TSC_OFFSET, tsc_offset),
	FIELD64(TSC_MULTIPLIER, tsc_multiplier),
	FIELD64(VIRTUAL_APIC_PAGE_ADDR, virtual_apic_page_addr),
	FIELD64(APIC_ACCESS_ADDR, apic_access_addr),
	FIELD64(POSTED_INTR_DESC_ADDR, posted_intr_desc_addr),
	FIELD64(VM_FUNCTION_CONTROL, vm_function_control),
	FIELD64(EPT_POINTER, ept_pointer),
	FIELD64(EOI_EXIT_BITMAP0, eoi_exit_bitmap0),
	FIELD64(EOI_EXIT_BITMAP1, eoi_exit_bitmap1),
	FIELD64(EOI_EXIT_BITMAP2, eoi_exit_bitmap2),
	FIELD64(EOI_EXIT_BITMAP3, eoi_exit_bitmap3),
	FIELD64(EPTP_LIST_ADDRESS, eptp_list_address),
	FIELD64(VMREAD_BITMAP, vmread_bitmap),
	FIELD64(VMWRITE_BITMAP, vmwrite_bitmap),
	FIELD64(XSS_EXIT_BITMAP, xss_exit_bitmap),
	FIELD64(ENCLS_EXITING_BITMAP, encls_exiting_bitmap),
	FIELD64(GUEST_PHYSICAL_ADDRESS, guest_physical_address),
	FIELD64(VMCS_LINK_POINTER, vmcs_link_pointer),
	FIELD64(GUEST_IA32_DEBUGCTL, guest_ia32_debugctl),
	FIELD64(GUEST_IA32_PAT, guest_ia32_pat),
	FIELD64(GUEST_IA32_EFER, guest_ia32_efer),
	FIELD64(GUEST_IA32_PERF_GLOBAL_CTRL, guest_ia32_perf_global_ctrl),
	FIELD64(GUEST_PDPTR0, guest_pdptr0),
	FIELD64(GUEST_PDPTR1, guest_pdptr1),
	FIELD64(GUEST_PDPTR2, guest_pdptr2),
	FIELD64(GUEST_PDPTR3, guest_pdptr3),
	FIELD64(GUEST_BNDCFGS, guest_bndcfgs),
	FIELD32(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control),
	FIELD32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control),
	FIELD32(EXCEPTION_BITMAP, exception_bitmap),
	FIELD32(PAGE_FAULT_ERROR_CODE_MASK, page_fault_error_code_mask),
	FIELD32(PAGE_FAULT_ERROR_CODE_MATCH, page_fault_error_code_match),
	FIELD32(CR3_TARGET_COUNT, cr3_target_count),
	FIELD32(VM_EXIT_CONTROLS, vm_exit_controls),
	FIELD32(VM_EXIT_MSR_STORE_COUNT, vm_exit_msr_store_count),
	FIELD32(VM_EXIT_MSR_LOAD_COUNT, vm_exit_msr_load_count),
	FIELD32(VM_ENTRY_CONTROLS, vm_entry_controls),
	FIELD32(VM_ENTRY_MSR_LOAD_COUNT, vm_entry_msr_load_count),
	FIELD32(VM_ENTRY_INTR_INFO_FIELD, vm_entry_intr_info_field),
	FIELD32(VM_ENTRY_EXCEPTION_ERROR_CODE, vm_entry_exception_error_code),
	FIELD32(VM_ENTRY_INSTRUCTION_LEN, vm_entry_instruction_len),
	FIELD32(TPR_THRESHOLD, tpr_threshold),
	FIELD32(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control),
	FIELD32(VM_INSTRUCTION_ERROR, vm_instruction_error),
	FIELD32(VM_EXIT_REASON, vm_exit_reason),
	FIELD32(VM_EXIT_INTR_INFO, vm_exit_intr_info),
	FIELD32(VM_EXIT_INTR_ERROR_CODE, vm_exit_intr_error_code),
	FIELD32(IDT_VECTORING_INFO_FIELD, idt_vectoring_info_field),
	FIELD32(IDT_VECTORING_ERROR_CODE, idt_vectoring_error_code),
	FIELD32(VM_EXIT_INSTRUCTION_LEN, vm_exit_instruction_len),
	FIELD32(VMX_INSTRUCTION_INFO, vmx_instruction_info),
	FIELD32(GUEST_ES_LIMIT, guest_es_limit),
	FIELD32(GUEST_CS_LIMIT, guest_cs_limit),
	FIELD32(GUEST_SS_LIMIT, guest_ss_limit),
	FIELD32(GUEST_DS_LIMIT, guest_ds_limit),
	FIELD32(GUEST_FS_LIMIT, guest_fs_limit),
	FIELD32(GUEST_GS_LIMIT, guest_gs_limit),
	FIELD32(GUEST_LDTR_LIMIT, guest_ldtr_limit),
	FIELD32(GUEST_TR_LIMIT, guest_tr_limit),
	FIELD32(GUEST_GDTR_LIMIT, guest_gdtr_limit),
	FIELD32(GUEST_IDTR_LIMIT, guest_idtr_limit),
	FIELD32(GUEST_ES_AR_BYTES, guest_es_ar_bytes),
	FIELD32(GUEST_CS_AR_BYTES, guest_cs_ar_bytes),
	FIELD32(GUEST_SS_AR_BYTES, guest_ss_ar_bytes),
	FIELD32(GUEST_DS_AR_BYTES, guest_ds_ar_bytes),
	FIELD32(GUEST_FS_AR_BYTES, guest_fs_ar_bytes),
	FIELD32(GUEST_GS_AR_BYTES, guest_gs_ar_bytes),
	FIELD32(GUEST_LDTR_AR_BYTES, guest_ldtr_ar_bytes),
	FIELD32(GUEST_TR_AR_BYTES, guest_tr_ar_bytes),
	FIELD32(GUEST_INTERRUPTIBILITY_INFO, guest_interruptibility_info),
	FIELD32(GUEST_ACTIVITY_STATE, guest_activity_state),
	FIELD32(GUEST_SYSENTER_CS, guest_sysenter_cs),
	FIELD32(VMX_PREEMPTION_TIMER_VALUE, vmx_preemption_timer_value),
	FIELDNAT(CR0_GUEST_HOST_MASK, cr0_guest_host_mask),
	FIELDNAT(CR4_GUEST_HOST_MASK, cr4_guest_host_mask),
	FIELDNAT(CR0_READ_SHADOW, cr0_read_shadow),
	FIELDNAT(CR4_READ_SHADOW, cr4_read_shadow),
	FIELDNAT(EXIT_QUALIFICATION, exit_qualification),
	FIELDNAT(GUEST_LINEAR_ADDRESS, guest_linear_address),
	FIELDNAT(GUEST_CR0, guest_cr0),
	FIELDNAT(GUEST_CR3, guest_cr3),
	FIELDNAT(GUEST_CR4, guest_cr4),
	FIELDNAT(GUEST_ES_BASE, guest_es_base),
	FIELDNAT(GUEST_CS_BASE, guest_cs_base),
	FIELDNAT(GUEST_SS_BASE, guest_ss_base),
	FIELDNAT(GUEST_DS_BASE, guest_ds_base),
	FIELDNAT(GUEST_FS_BASE, guest_fs_base),
	FIELDNAT(GUEST_GS_BASE, guest_gs_base),
	FIELDNAT(GUEST_LDTR_BASE, guest_ldtr_base),
	FIELDNAT(GUEST_TR_BASE, guest_tr_base),
	FIELDNAT(GUEST_GDTR_BASE, guest_gdtr_base),
	FIELDNAT(GUEST_IDTR_BASE, guest_idtr_base),
	FIELDNAT(GUEST_DR7, guest_dr7),
	FIELDNAT(GUEST_RSP, guest_rsp),
	FIELDNAT(GUEST_RIP, guest_rip),
	FIELDNAT(GUEST_RFLAGS, guest_rflags),
	FIELDNAT(GUEST_PENDING_DBG_EXCEPTIONS, guest_pending_dbg_exceptions),
	FIELDNAT(GUEST_SYSENTER_ESP, guest_sysenter_esp),
	FIELDNAT(GUEST_SYSENTER_EIP, guest_sysenter_eip),
};

const unsigned short index_gp_map[ARCH_GP_SIZE] = {
  FIELD_GP(REG_GP_RAX),
  FIELD_GP(REG_GP_RBX),
  FIELD_GP(REG_GP_RCX),
  FIELD_GP(REG_GP_RDX),
  FIELD_GP(REG_GP_RBP),
  FIELD_GP(REG_GP_RSI),
  FIELD_GP(REG_GP_RDI),
  FIELD_GP(REG_GP_R8),
  FIELD_GP(REG_GP_R9),
  FIELD_GP(REG_GP_R10),
  FIELD_GP(REG_GP_R11),
  FIELD_GP(REG_GP_R12),
  FIELD_GP(REG_GP_R13),
  FIELD_GP(REG_GP_R14),
  FIELD_GP(REG_GP_R15),
}; 

static inline enum cache_width get_field_width(unsigned long field) {
  if (field >= REG_GP_RAX && field <= REG_GP_R15) {
    return WIDTH_GP; 
  }
  if (0x1 & field) /* The _HIGH fields are all 32 bits.*/
    return WIDTH_32;
  return (field >> 13) & 0x3;
} 

int cache_is_updated(arch_cache_t *cache, unsigned long field) {
  int idx = 0;
  u64 bit = 0;
  enum cache_width width = get_field_width(field);
  if (cache == NULL) {
    goto failure;
  }
  idx = (width == WIDTH_GP)? index_gp_map[OFFSET_GP(field)] : index_map[ROL16(field, 6)];
  if ((idx & VALID_MASK) == 0) {
    goto failure;
  }
  idx ^= VALID_MASK;
  switch(width) {
    case WIDTH_GP:
      bit = idx / sizeof(unsigned long);
      if (bit >= ARCH_GP_SIZE) {
        return 0;
      }
      if ((cache->bits_gp.read & (1ULL << bit)) == 0) {
        return 0;
      }
      return 1;
      break;
	case WIDTH_NAT:
    bit = idx / sizeof(natural_width); 
    if (bit >= ARCH_NAT_SIZE) {
      return -1;
    }
    if ((cache->bits_nat.read & (1ULL << bit)) == 0) {
      return 0;
    }
    return 1;
    break;
	case WIDTH_16:
    bit = idx / sizeof(u16); 
    if (bit >= ARCH_16_SIZE) {
      return -1;
    }
    if ((cache->bits_16.read & (1ULL << bit)) == 0) {
      return 0;
    } 
    return 1;
    break;
	case WIDTH_32:
    bit = idx / sizeof(u32); 
    if (bit >= ARCH_32_SIZE) {
      return -1;
    }
    if ((cache->bits_32.read & (1ULL << bit)) == 0) {
      return 0;
    }
    return 1;
    break;
	case WIDTH_64:
    bit = idx / sizeof(u64); 
    if (bit >= ARCH_64_SIZE) {
      return -1;
    }
    if ((cache->bits_64.read & (1ULL << bit)) == 0) {
      return 0;
    }
    return 1;
    break;
	default:
		return -1;
  }
failure:
  return -1;
}

int cache_read_any(arch_cache_t *cache, unsigned long field, u64* result)
{
  int idx = 0;
  u64 bit = 0;
  char* ptr = NULL;
  enum cache_width width = get_field_width(field);
  if (cache == NULL || result == NULL) {
    return -1;
  }

  //TODO(aghosn) should have a check here for both indices.
  idx = (width == WIDTH_GP)? index_gp_map[OFFSET_GP(field)] : index_map[ROL16(field, 6)];
  if ((idx & VALID_MASK) == 0) {
    return -1;
  }
  idx ^= VALID_MASK;
	switch (width) {
  case WIDTH_GP:
    bit = idx / sizeof(unsigned long);
    ptr = ((char*) &(cache->cache_gp.regs)) + idx;
    if (bit >= ARCH_GP_SIZE || (cache->bits_gp.read & (1ULL << bit)) == 0) {
      return -1;
    }
    *result = *(unsigned long*) ptr; 
    break;
	case WIDTH_NAT:
    bit = idx / sizeof(natural_width); 
    ptr = ((char*) &(cache->cache_nat)) + idx;
    if (bit >= ARCH_NAT_SIZE || (cache->bits_nat.read & (1ULL << bit)) == 0) {
      return -1; 
    }
		*result = *((natural_width *)ptr);
    break;
	case WIDTH_16:
    bit = idx / sizeof(u16); 
    ptr = ((char*) &(cache->cache_16)) + idx;
    if (bit >= ARCH_16_SIZE || (cache->bits_16.read & (1ULL << bit)) == 0) {
      return -1; 
    }
		*result = *((u16 *)ptr);
    break;
	case WIDTH_32:
    bit = idx / sizeof(u32); 
    ptr = ((char*) &(cache->cache_32)) + idx;
    if (bit >= ARCH_32_SIZE || (cache->bits_32.read & (1ULL << bit)) == 0) {
      return -1; 
    }
		*result = *((u32 *)ptr);
    break;
	case WIDTH_64:
    bit = idx / sizeof(u64); 
    ptr = ((char*) &(cache->cache_64)) + idx;
    if (bit >= ARCH_64_SIZE || (cache->bits_64.read & (1ULL << bit)) == 0) {
      return -1; 
    }
		*result = *((u64*)ptr);
    break;
	default:
		return -1;
	}
  return 0;
}

static inline int cache_write_internal(arch_cache_t *cache, unsigned long field, u64 field_value, bool dirty)
{
  unsigned short idx = 0;
  unsigned int bit = 0;
  char* ptr = NULL;
  enum cache_width width = get_field_width(field);
  if (cache == NULL) {
    ERROR("NULL cache.");
    return -1;
  }
  idx = (width == WIDTH_GP)? index_gp_map[OFFSET_GP(field)] : index_map[ROL16(field, 6)];
  if ((idx & VALID_MASK) == 0) {
    return -2;
  }
  idx ^= VALID_MASK;
	switch (width) {
  case WIDTH_GP:
    bit = idx / sizeof(unsigned long);
    ptr = ((char*) &(cache->cache_gp.regs)) + idx;
    if (bit >= ARCH_GP_SIZE) {
      return -1;
    }
    // The value is already up-to-date.
    if (((cache->bits_gp.read & (1ULL << bit)) != 0) && (*(unsigned long*) ptr) == field_value) {
      break;
    }
    cache->bits_gp.read |= (1ULL << bit);
    if (dirty) {
      cache->bits_gp.written |= (1ULL << bit);
    }
    *(unsigned long*) ptr = field_value; 
    break;
	case WIDTH_NAT:
    bit = idx / sizeof(natural_width); 
    ptr = ((char*) &(cache->cache_nat)) + idx;
    if (bit >= ARCH_NAT_SIZE) {
      return -3; 
    }
    // The value is already up-to-date.
    if (((cache->bits_nat.read & (1ULL << bit)) != 0) && (*(natural_width*) ptr) == field_value) {
      break;
    }
    cache->bits_nat.read |= (1ULL << bit);
    if (dirty) {
      cache->bits_nat.written |= (1ULL << bit);
    }
	  *(natural_width *)ptr = field_value;
    break;
	case WIDTH_16:
    bit = idx / sizeof(u16); 
    ptr = ((char*) &(cache->cache_16)) + idx;
    if (bit >= ARCH_16_SIZE) {
      return -4; 
    }
    // The value is already up-to-date.
    if (((cache->bits_16.read & (1ULL << bit)) != 0) && (*(u16*) ptr) == field_value) {
      break;
    }
    cache->bits_16.read |= (1ULL << bit);
    if (dirty) {
      cache->bits_16.written |= (1ULL << bit);
    }
		*(u16 *)ptr = field_value;
    break;
	case WIDTH_32:
    bit = idx / sizeof(u32); 
    ptr = ((char*) &(cache->cache_32)) + idx;
    if (bit >= ARCH_32_SIZE) {
      return -5; 
    }
    // The value is already up-to-date.
    if (((cache->bits_32.read & (1ULL << bit)) != 0) && (*(u32*) ptr) == field_value) {
      break;
    }
    cache->bits_32.read |= (1ULL << bit);
    if (dirty) {
      cache->bits_32.written |= (1ULL << bit);
    }
		*(u32 *)ptr = field_value;
    break;
	case WIDTH_64:
    bit = idx / sizeof(u64); 
    ptr = ((char*) &(cache->cache_64)) + idx;
    if (bit >= ARCH_64_SIZE) {
      return -6; 
    }
    // The value is already up-to-date.
    if (((cache->bits_64.read & (1ULL << bit)) != 0) && (*(u64*) ptr) == field_value) {
      break;
    }
    cache->bits_64.read |= (1ULL << bit);
    if (dirty) {
      cache->bits_64.written |= (1ULL << bit);
    }
		*(u64*)ptr = field_value;
    break;
	default:
		return -7;
	}
  return 0;
}

int cache_write_any(arch_cache_t *cache, unsigned long field, u64 field_value) {
  return cache_write_internal(cache, field, field_value, true);
}

int cache_set_any(arch_cache_t *cache, unsigned long field, u64 field_value) {
  return cache_write_internal(cache, field, field_value, false);
}

static inline unsigned int count_ones(u64 bitmap, int limit) {
  int i = 0;
  unsigned int result = 0;
  while(bitmap != 0 && i < limit) {
    i++;
    result += (bitmap & 1);
    bitmap >>= 1;
  }
  return result;
}

unsigned int cache_dirty_count(arch_cache_t* cache) {
  unsigned int res = 0;
  if (cache == NULL) {
    goto done;
  } 
  // GP-registers.
  if (cache->bits_gp.written != 0) {
    res += count_ones(cache->bits_gp.written, ARCH_GP_SIZE);
  }
  // 64-bits.
  if (cache->bits_64.written != 0) {
    res += count_ones(cache->bits_64.written, ARCH_64_SIZE); 
  }

  // Nat-bits.
  if (cache->bits_nat.written != 0) {
    res += count_ones(cache->bits_nat.written, ARCH_NAT_SIZE); 
  }

  // 32-bits.
  if (cache->bits_32.written != 0) {
    res += count_ones(cache->bits_32.written, ARCH_32_SIZE);
  }

  // 16-bits.
  if (cache->bits_16.written != 0) {
    res += count_ones(cache->bits_16.written, ARCH_16_SIZE);
  }

done:
  return res;
}

#define CACHE_COLLECT(arch_bitmap, max_size, idx, capacity, values, fields, cache, cache_names) \
  do {                                                                                          \
    int i = 0;                                                                                  \
    u64 bitmap = arch_bitmap;                                                                   \
    while(bitmap != 0 && i < max_size && idx < capacity) {                                      \
      if (bitmap & 1) {                                                                         \
        values[idx] = cache[i];                                                              \
        fields[idx] = cache_names[i];                                                           \
        idx++;                                                                                  \
      }                                                                                         \
      i++;                                                                                      \
      bitmap >>= 1;                                                                             \
    }                                                                                           \
  } while(0);

int cache_collect_dirties(arch_cache_t* cache, u64* values, u64* fields, int capacity) {
  int idx = 0;
  if (cache == NULL || values == NULL || fields == NULL || capacity <= 0) {
    goto failure;
  }
  if (cache->bits_gp.written != 0) {
    unsigned long *regs = cache->cache_gp.regs; 
    CACHE_COLLECT(cache->bits_gp.written, ARCH_GP_SIZE, idx, capacity, values, fields, regs, arch_gp_names);
    if (idx >= capacity) {
      return -1;
    }
  }
  // 64-bits.
  if (cache->bits_64.written != 0) {
    u64* regs = (u64*)&(cache->cache_64);
    CACHE_COLLECT(cache->bits_64.written, ARCH_64_SIZE, idx, capacity, values, fields, regs, arch_64_names); 
    if (idx >= capacity) {
      return -1;
    }
  }
  // Nat-bits.
  if (cache->bits_nat.written != 0) {
    natural_width* regs = (natural_width*)&(cache->cache_nat);
    CACHE_COLLECT(cache->bits_nat.written, ARCH_NAT_SIZE, idx, capacity, values, fields, regs, arch_nat_names);
    if (idx >= capacity) {
      return -1;
    }
  }
  // 32-bits.
  if (cache->bits_32.written != 0) {
    u32* regs = (u32*)&(cache->cache_32);
    CACHE_COLLECT(cache->bits_32.written, ARCH_32_SIZE, idx, capacity, values, fields, regs, arch_32_names);
    if (idx >= capacity) {
      return -1;
    }
  }
  // 16-bits.
  if (cache->bits_16.written != 0) {
    u16* regs = (u16*)&(cache->cache_16);
    CACHE_COLLECT(cache->bits_16.written, ARCH_16_SIZE, idx, capacity, values, fields, regs, arch_16_names);
    if (idx >= capacity) {
      return -1;
    }
  }
  return idx;
failure:
  return -1;
}

void cache_clear(arch_cache_t* cache, int read) {
  if (cache == NULL)
    return;
  cache->bits_16.written = 0;
  cache->bits_32.written = 0;
  cache->bits_64.written = 0;
  cache->bits_nat.written = 0;
  cache->bits_gp.written = 0;
  if (read) {
    cache->bits_16.read = 0;
    cache->bits_32.read = 0;
    cache->bits_64.read = 0;
    cache->bits_nat.read = 0;
    cache->bits_gp.read = 0;
  }
}

void erase_all(arch_cache_t* cache) {
  if (cache == NULL) 
    return;
  memset(cache, 0, sizeof(arch_cache_t));
}
