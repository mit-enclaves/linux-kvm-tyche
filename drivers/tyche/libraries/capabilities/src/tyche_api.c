#include "tyche_api.h"
#include "common.h"
#include "common_log.h"
#include "tyche_capabilities_types.h"

/// Simple generic vmcall implementation.
int tyche_call(vmcall_frame_t* frame)
{
  usize result = FAILURE;
#if defined(CONFIG_X86) || defined(__x86_64__)
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
    : "=rm" (result), "=rm" (frame->value_1), "=rm" (frame->value_2), "=rm" (frame->value_3), "=rm" (frame->value_4), "=rm" (frame->value_5), "=rm" (frame->value_6)
    : "rm" (frame->vmcall), "rm" (frame->arg_1), "rm" (frame->arg_2), "rm" (frame->arg_3), "rm" (frame->arg_4), "rm" (frame->arg_5), "rm" (frame->arg_6) 
    : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
#elif defined(CONFIG_RISCV) || defined(__riscv)
    asm volatile(
        "addi sp, sp, -9*8\n\t"
        "sd a0, 0*8(sp)\n\t"
        "sd a1, 1*8(sp)\n\t"
        "sd a2, 2*8(sp)\n\t"
        "sd a3, 3*8(sp)\n\t"
        "sd a4, 4*8(sp)\n\t"
        "sd a5, 5*8(sp)\n\t"
        "sd a6, 6*8(sp)\n\t"
        "sd a7, 7*8(sp)\n\t"
        "mv a0, %[sa0]\n\t"
        "mv a1, %[sa1]\n\t"
        "mv a2, %[sa2]\n\t"
        "mv a3, %[sa3]\n\t"
        "mv a4, %[sa4]\n\t"
        "mv a5, %[sa5]\n\t" 
        "mv a6, %[sa6]\n\t"
	    "li a7, 0x5479636865\n\t"
        "ecall\n\t"
        "mv %[da0], a0\n\t"
        "mv %[da1], a1\n\t"
        "mv %[da2], a2\n\t"
        "mv %[da3], a3\n\t"
        "mv %[da4], a4\n\t" 
        "mv %[da5], a5\n\t"
        "mv %[da6], a6\n\t"
        "ld a0, 0*8(sp)\n\t"
        "ld a1, 1*8(sp)\n\t"
        "ld a2, 2*8(sp)\n\t"
        "ld a3, 3*8(sp)\n\t"
        "ld a4, 4*8(sp)\n\t"
        "ld a5, 5*8(sp)\n\t"
        "ld a6, 6*8(sp)\n\t"
        "ld a7, 7*8(sp)\n\t"
        "addi sp, sp, 9*8\n\t"

        : [da0]"=r" (result), [da1]"=r" (frame->value_1), [da2]"=r" (frame->value_2), [da3]"=r" (frame->value_3), [da4]"=r" (frame->value_4), [da5]"=r" (frame->value_5), [da6]"=r" (frame->value_6)
        :  [sa0]"r" (frame->vmcall), [sa1]"r" (frame->arg_1), [sa2]"r" (frame->arg_2), [sa3]"r" (frame->arg_3), [sa4]"r" (frame->arg_4), [sa5]"r" (frame->arg_5), [sa6]"r" (frame->arg_6)   
	    : "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"
    );
#endif
  return (int)result;
} 

/// Simple generic vmcall implementation with cli.
int tyche_call_cli(vmcall_frame_t* frame)
{
  usize result = FAILURE;
#if defined(CONFIG_X86) || defined(__x86_64__)
  asm volatile(
    // Setting arguments.
    "movq %7, %%rax\n\t"
    "movq %8, %%rdi\n\t"
    "movq %9, %%rsi\n\n"
    "movq %10, %%rdx\n\t"
    "movq %11, %%rcx\n\t"
    "movq %12, %%r8\n\t"
    "movq %13, %%r9\n\t"
    "cli\n\t"
    "vmcall\n\t"
    // Receiving results.
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%rsi, %2\n\t"
    "movq %%rdx, %3\n\t"
    "movq %%rcx, %4\n\t"
    "movq %%r8,  %5\n\t"
    "movq %%r9,  %6\n\t"
    "sti\n\t"
    : "=rm" (result), "=rm" (frame->value_1), "=rm" (frame->value_2), "=rm" (frame->value_3), "=rm" (frame->value_4), "=rm" (frame->value_5), "=rm" (frame->value_6)
    : "rm" (frame->vmcall), "rm" (frame->arg_1), "rm" (frame->arg_2), "rm" (frame->arg_3), "rm" (frame->arg_4), "rm" (frame->arg_5), "rm" (frame->arg_6) 
    : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
#elif defined(CONFIG_RISCV) || defined(__riscv)
  asm volatile(
        "addi sp, sp, -9*8\n\t"
        "sd a0, 0*8(sp)\n\t"
        "sd a1, 1*8(sp)\n\t"
        "sd a2, 2*8(sp)\n\t"
        "sd a3, 3*8(sp)\n\t"
        "sd a4, 4*8(sp)\n\t"
        "sd a5, 5*8(sp)\n\t"
        "sd a6, 6*8(sp)\n\t"
        "sd a7, 7*8(sp)\n\t"
        "mv a0, %[sa0]\n\t"
        "mv a1, %[sa1]\n\t"
        "mv a2, %[sa2]\n\t"
        "mv a3, %[sa3]\n\t"
        "mv a4, %[sa4]\n\t"
        "mv a5, %[sa5]\n\t" 
        "mv a6, %[sa6]\n\t"
	    "li a7, 0x5479636865\n\t"
        "ecall\n\t"
        "mv %[da0], a0\n\t"
        "mv %[da1], a1\n\t"
        "mv %[da2], a2\n\t"
        "mv %[da3], a3\n\t"
        "mv %[da4], a4\n\t" 
        "mv %[da5], a5\n\t"
        "mv %[da6], a6\n\t"
        "ld a0, 0*8(sp)\n\t"
        "ld a1, 1*8(sp)\n\t"
        "ld a2, 2*8(sp)\n\t"
        "ld a3, 3*8(sp)\n\t"
        "ld a4, 4*8(sp)\n\t"
        "ld a5, 5*8(sp)\n\t"
        "ld a6, 6*8(sp)\n\t"
        "ld a7, 7*8(sp)\n\t"
        "addi sp, sp, 9*8\n\t"

        : [da0]"=r" (result), [da1]"=r" (frame->value_1), [da2]"=r" (frame->value_2), [da3]"=r" (frame->value_3), [da4]"=r" (frame->value_4), [da5]"=r" (frame->value_5), [da6]"=r" (frame->value_6)
        :  [sa0]"r" (frame->vmcall), [sa1]"r" (frame->arg_1), [sa2]"r" (frame->arg_2), [sa3]"r" (frame->arg_3), [sa4]"r" (frame->arg_4), [sa5]"r" (frame->arg_5), [sa6]"r" (frame->arg_6)   
	    : "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"
    );
#endif
  return (int)result;
} 

int tyche_create_domain(capa_index_t* management, int aliased) {
  vmcall_frame_t frame;
  if (management == NULL) {
    goto fail;
  }
  frame.vmcall = TYCHE_CREATE_DOMAIN;
  frame.arg_1 = aliased;
  if (tyche_call(&frame) != SUCCESS) {
    goto fail;
  }
  *management = frame.value_1;
  return SUCCESS;
fail:
  return FAILURE;
}

int tyche_set_domain_config(capa_index_t management, tyche_configurations_t idx,
			    usize value)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_CONFIGURE,
    .arg_1 = idx,
    .arg_2 = management,
    .arg_3 = value,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_set_self_core_config(usize field, usize value)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SELF_CONFIG,
    .arg_1 = field,
    .arg_2 = value,
  };
  return tyche_call(&frame);
}

int tyche_set_domain_core_config(capa_index_t management, usize core, usize idx, usize value)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_CONFIGURE_CORE,
    .arg_1 = management,
    .arg_2 = core,
    .arg_3 = idx,
    .arg_4 = value,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_write_fields(capa_index_t management, usize core, usize* fields, usize* values, int size) {
#if defined(CONFIG_X86) || defined(__x86_64__)
  usize frame[3] = {TYCHE_WRITE_FIELDS, management, core};
  if (size > 6) {
    ERROR("Wrong size for tyche write fields.");
    goto failure;
  }
  asm volatile(
    // Push all the registers we want to save.
    // Start with rax that we globber several times.
    "pushq %%rax\n\t"
    "pushq %%rdi\n\t"
    "pushq %%rsi\n\t"
    "pushq %%rbp\n\t"
    "pushq %%rbx\n\t"
    "pushq %%rcx\n\t"
    "pushq %%rdx\n\t"
    "pushq %%r8\n\t"
    "pushq %%r9\n\t"
    "pushq %%r10\n\t"
    "pushq %%r11\n\t"
    "pushq %%r12\n\t"
    "pushq %%r13\n\t"
    "pushq %%r14\n\t"
    "pushq %%r15\n\t"
    // Get the arguments in registers.
    "movq %0, %%rax\n\t"
    "movq %1, %%rdi\n\t"
    "movq %2, %%rsi\n\t"
    // Push the result array and arguments for later.
    "pushq %%rax\n\t"
    "pushq (%%rax)\n\t"
    "pushq 8(%%rax)\n\t"
    "pushq 16(%%rax)\n\t"
    //Set the arguments
    // First couple (rbp, rbx).
    "movq (%%rdi), %%rbp\n\t"
    "movq (%%rsi), %%rbx\n\t"
    // Second couple (rcx, rdx)
    "movq 8(%%rdi), %%rcx\n\t"
    "movq 8(%%rsi), %%rdx\n\t"
    // Third couple (r8, r9)
    "movq 16(%%rdi), %%r8\n\t"
    "movq 16(%%rsi), %%r9\n\t"
    // Fourth couple (r10, r11)
    "movq 24(%%rdi), %%r10\n\t"
    "movq 24(%%rsi), %%r11\n\t"
    // Fifth couple (r12, r13)
    "movq 32(%%rdi), %%r12\n\t"
    "movq 32(%%rsi), %%r13\n\t"
    // Sixth couple (r14, r15)
    "movq 40(%%rdi), %%r14\n\t"
    "movq 40(%%rsi), %%r15\n\t"
    // Now pop the call arguments.
    "popq %%rsi\n\t"
    "popq %%rdi\n\t"
    "popq %%rax\n\t"
    // Do the vmcall.
    "vmcall\n\t"
    // Save registers we globber.
    "pushq %%rax\n\t"
    "pushq %%rdi\n\t"
    // Put the return value in the pointer.
    "movq 16(%%rsp), %%rax\n\t"
    "movq 8(%%rsp), %%rdi\n\t"
    "movq %%rdi, (%%rax)\n\t"
    // Pop the registers.
    "popq %%rdi\n\t"
    "popq %%rax\n\t"
    // Discard the result pointer.
    "popq %%rax\n\t"
    // Reload all registers.
    "popq %%r15\n\t"
    "popq %%r14\n\t"
    "popq %%r13\n\t"
    "popq %%r12\n\t"
    "popq %%r11\n\t"
    "popq %%r10\n\t"
    "popq %%r9\n\t"
    "popq %%r8\n\t"
    "popq %%rdx\n\t"
    "popq %%rcx\n\t"
    "popq %%rbx\n\t"
    "popq %%rbp\n\t"
    "popq %%rsi\n\t"
    "popq %%rdi\n\t"
    "popq %%rax\n\t"
    : 
    : "rm" (frame), "rm" (fields), "rm" (values)
    : "rax", "rdi", "memory"
      );
  return frame[0];
#elif defined(CONFIG_RISCV) || defined(__riscv)
  int i = 0;
  // On risc-v we don't care about performance, we write one field at the time.
  for (i = 0; i < size; i++) {
    vmcall_frame_t frame = {
      .vmcall = TYCHE_WRITE_FIELDS,
      .arg_1 = management,
      .arg_2 = core,
      .arg_3 = fields[i],
      .arg_4 = values[i],
    };
    if (tyche_call(&frame) != SUCCESS) {
      goto failure;
    }
  }
  return SUCCESS;
#endif
failure:
  return FAILURE;
}

int tyche_get_domain_core_config(capa_index_t management, usize core, usize idx, usize *value)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_GET_CONFIG_CORE,
    .arg_1 = management,
    .arg_2 = core,
    .arg_3 = idx,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *value = frame.value_1; 
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_alloc_core_context(capa_index_t management, usize core) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_ALLOC_CORE_CONTEXT,
    .arg_1 = management,
    .arg_2 = core,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}


int tyche_seal(capa_index_t* transition, capa_index_t management)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEAL_DOMAIN,
    .arg_1 = management,
  };
  if (transition == NULL) {
    goto failure;
  }

  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *transition = frame.value_1;
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_segment_region(
    usize is_shared,
    capa_index_t capa,
    capa_index_t* to_send,
    capa_index_t* revoke,
    usize start,
    usize end,
    usize prot)
{
  vmcall_frame_t frame = {
    TYCHE_SEGMENT_REGION,
    capa,
    is_shared,
    start,
    end,
    prot,
  };
  if (to_send == NULL || revoke == NULL) {
    goto failure;
  }
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  } 
  *to_send = frame.value_1;
  *revoke = frame.value_2;
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_send(capa_index_t dest, capa_index_t capa) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEND,
    .arg_1 = capa,
    .arg_2 = dest,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  // Check that the revocation handle is the original one.
  if (frame.value_1 != capa) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_send_aliased(capa_index_t dest, capa_index_t capa, int is_repeat,
		usize alias, usize size) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEND_REGION,
    .arg_1 = capa,
    .arg_2 = dest,
    .arg_3 = alias,
    .arg_4 = is_repeat,
    .arg_5 = size,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  // Check that the revocation handle is the original one.
  if (frame.value_1 != capa) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_duplicate(capa_index_t* new_capa, capa_index_t capa) {
  vmcall_frame_t frame = {
   .vmcall = TYCHE_DUPLICATE, 
  };
  if (new_capa == NULL || tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *new_capa = frame.arg_1;

  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_revoke(capa_index_t id)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_REVOKE,
    .arg_1 = id,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_revoke_region(capa_index_t id, capa_index_t child, paddr_t gpa, paddr_t size)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_REVOKE_ALIASED_REGION,
    .arg_1 = id,
    .arg_2 = child,
    .arg_3 = gpa,
    .arg_4 = size,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_serialize_attestation(usize addr, usize size, usize *written)
{
    vmcall_frame_t frame = {
        .vmcall = TYCHE_SERIALIZE_ATTESTATION,
        .arg_1 = addr,
        .arg_2 = size,
    };
    if (tyche_call(&frame) != SUCCESS) {
        goto failure;
    }
    *written = frame.value_1;
    return SUCCESS;
failure:
    *written = 0;
    return FAILURE;
}

int tyche_read_gp_registers(capa_index_t management, usize core, usize regs[TYCHE_GP_REGS_SIZE]) {
#if defined(CONFIG_X86) || defined(__x86_64__)
  vmcall_frame_t frame = {
    .vmcall = TYCHE_READ_ALL,
    .arg_1 = management,
    .arg_2 = core,
  };
  if (regs == NULL) {
    ERROR("Received null transition and/or regs");
    return FAILURE;
  }
  asm volatile (
    // Save all the registers on the stack.
   "pushq %%rax\n\t"
   "pushq %%rdi\n\t"
   "pushq %%rsi\n\t"
   "pushq %%rbp\n\t"
   "pushq %%rbx\n\t"
   "pushq %%rcx\n\t"
   "pushq %%rdx\n\t"
   "pushq %%r8\n\t"
   "pushq %%r9\n\t"
   "pushq %%r10\n\t"
   "pushq %%r11\n\t"
   "pushq %%r12\n\t"
   "pushq %%r13\n\t"
   "pushq %%r14\n\t"
   "pushq %%r15\n\t"
   // Save the array on the stack.
   "movq %3, %%rax\n\t"
   "pushq %%rax\n\t"
   // Put the arguments in registers.
   "movq %0, %%rax\n\t"
   "movq %1, %%rdi\n\t"
   "movq %2, %%rsi\n\t"
   "vmcall\n\t"
   // Save the current rax on the stack
   "pushq %%rax\n\t"
   // Read the array back into rax.
    "movq 8(%%rsp), %%rax\n\t"
   // Save the registers in the array.
   "movq %%rbx, 8(%%rax)\n\t"
   "movq %%rcx, 16(%%rax)\n\t"
   "movq %%rdx, 24(%%rax)\n\t"
   "movq %%rbp, 32(%%rax)\n\t"
   "movq %%rsi, 40(%%rax)\n\t"
   "movq %%rdi, 48(%%rax)\n\t"
   "movq %%r8, 56(%%rax)\n\t"
   "movq %%r9, 64(%%rax)\n\t"
   "movq %%r10, 72(%%rax)\n\t"
   "movq %%r11, 80(%%rax)\n\t"
   "movq %%r12, 88(%%rax)\n\t"
   "movq %%r13, 96(%%rax)\n\t"
   "movq %%r14, 104(%%rax)\n\t"
   "movq %%r15, 112(%%rax)\n\t"
    // Save rax in the array.
    "popq %%rdi\n\t"
    "movq %%rdi, (%%rax)\n\t"
   // Discard the array
   "popq %%rax\n\t"
   // Pop the caller's stack value.
   "popq %%r15\n\t"
   "popq %%r14\n\t"
   "popq %%r13\n\t"
   "popq %%r12\n\t"
   "popq %%r11\n\t"
   "popq %%r10\n\t"
   "popq %%r9\n\t"
   "popq %%r8\n\t"
   "popq %%rdx\n\t"
   "popq %%rcx\n\t"
   "popq %%rbx\n\t"
   "popq %%rbp\n\t"
   "popq %%rsi\n\t"
   "popq %%rdi\n\t"
   "popq %%rax\n\t"
   :
   : "rm" (frame.vmcall), "rm" (frame.arg_1), "rm" (frame.arg_2), "rm" (regs)
   : "rax", "rdi"
      );
#elif defined(CONFIG_RISCV) || defined(__riscv)
  //TODO ignored on riscv for the moment.
#endif
  return SUCCESS;
}

//TODO rewrite to use the right registers.
/// TODO there is an opportunity for unused registers here.
/// That could be part of a write registers if we need it.
int tyche_switch(capa_index_t* transition_handle, usize exit_frame[TYCHE_EXIT_FRAME_SIZE])
{
#if defined(CONFIG_X86) || defined(__x86_64__)
  int result = FAILURE;
  usize results[2] = {TYCHE_SWITCH, 0};
  if (transition_handle == NULL) {
    ERROR("Received null handle");
    return FAILURE;
  }
  results[1] = *transition_handle;

  asm volatile(
    // Push all the registers on the stack.
    // Start with rax, that we globber several times.
    "pushq %%rax\n\t"
    "pushq %%rdi\n\t"
    "pushq %%rsi\n\t"
    "pushq %%rbp\n\t"
    "pushq %%rbx\n\t"
    "pushq %%rcx\n\t"
    "pushq %%rdx\n\t"
    "pushq %%r8\n\t"
    "pushq %%r9\n\t"
    "pushq %%r10\n\t"
    "pushq %%r11\n\t"
    "pushq %%r12\n\t"
    "pushq %%r13\n\t"
    "pushq %%r14\n\t"
    "pushq %%r15\n\t"
    // Push the arrays, first the main one, then the result one.
    "movq %1, %%rax\n\t"
    "pushq %%rax\n\t"
    "movq %0, %%rax\n\t"
    "pushq %%rax\n\t"
    // Set the arguments.
    "movq 8(%%rax), %%rdi\n\t"
    "movq 0(%%rax), %%rsi\n\t"
    "movq %%rsi, %%rax\n\t"
    // Do the call.
    "vmcall\n\t"
    // We are back. Let's save the values.
    // Start by saving the current rax.
    "pushq %%rax\n\t"
    "pushq %%rdi\n\t"
    // Read the array back into rax.
    "movq 16(%%rsp), %%rax\n\t"
    // Save the return handle.
    "movq %%rdi, 8(%%rax)\n\t"
    // Save the return value rax.
    "movq 8(%%rsp), %%rdi\n\t"
    "movq %%rdi, (%%rax)\n\t"
    // Restore rdi.
    "popq %%rdi\n\t"
    // Discard rax, we saved it, discard the result array, we're done.
    "popq %%rax\n\t"
    "popq %%rax\n\t"
    // Get the exit frame array.
    "popq %%rax\n\t"
    // Save the potential interrupt frame.
    "movq %%rbx, 0(%%rax)\n\t" // guest rip.
    "movq %%rcx, 8(%%rax)\n\t" // guest rsp.
    "movq %%rdx, 16(%%rax)\n\t" // guest rflags.
    "movq %%rsi, 24(%%rax)\n\t" // guest vm instruction error.
    "movq %%r8, 32(%%rax)\n\t" // vm exit reason.
    "movq %%r9, 40(%%rax)\n\t" // vm exit intr info.
    "movq %%r10, 48(%%rax)\n\t" // vm exit intr error code.
    "movq %%r11, 56(%%rax)\n\t" // vm exit instruction len.
    "movq %%r12, 64(%%rax)\n\t" // vm instruction error.
    // Now put back all the registers.
    "popq %%r15\n\t"
    "popq %%r14\n\t"
    "popq %%r13\n\t"
    "popq %%r12\n\t"
    "popq %%r11\n\t"
    "popq %%r10\n\t"
    "popq %%r9\n\t"
    "popq %%r8\n\t"
    "popq %%rdx\n\t"
    "popq %%rcx\n\t"
    "popq %%rbx\n\t"
    "popq %%rbp\n\t"
    "popq %%rsi\n\t"
    "popq %%rdi\n\t"
    "popq %%rax\n\t"
    :
    : "rm" (results), "rm" (exit_frame) 
    : "rax", "memory"
      );

  result = results[0];
  *transition_handle = results[1];
#elif defined(CONFIG_RISCV) || defined(__riscv)
  usize result = FAILURE;
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SWITCH,
    .arg_1 = 0,
  };
  if (transition_handle == NULL) {
    ERROR("Received null handle");
    return FAILURE;
  }
  frame.arg_1 = *transition_handle;
  if (tyche_call(&frame) != SUCCESS) {
    return FAILURE;
  } 
  *transition_handle = frame.value_1;
  exit_frame[0] = frame.value_2;
  exit_frame[1] = frame.value_3;
  exit_frame[2] = frame.value_4;
  exit_frame[3] = frame.value_5;
#endif
  return result;
}
