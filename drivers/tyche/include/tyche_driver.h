#ifndef __INCLUDE_TYCHE_DRIVER_H__
#define __INCLUDE_TYCHE_DRIVER_H__

#ifdef _IN_MODULE
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#include "tyche_capabilities_types.h"

// ———————————————————— Constants Defined in the Module ————————————————————— //
#define TE_READ ((uint64_t)MEM_READ)
#define TE_WRITE ((uint64_t)MEM_WRITE)
#define TE_EXEC ((uint64_t)MEM_EXEC)
#define TE_SUPER ((uint64_t)MEM_SUPER)
#define TE_DEFAULT ((uint64_t)(TE_READ | TE_WRITE | TE_EXEC))

// —————————————————————— Types Exposed by the Library —————————————————————— //
typedef struct file *domain_handle_t;

// ———————————————————————————————— Messages ———————————————————————————————— //

/// Default message used to communicate with the driver.
typedef struct {
	usize virtaddr;
	usize physoffset;
} msg_info_t;

/// Message type to add a new region.
typedef struct {
	/// Start virtual address. Must be page aligned and within the mmaped region.
	usize start;

	/// Must be page aligned, greater than start, and within the mmaped region.
	usize size;

	/// Access right (RWXU) for this region.
	memory_access_right_t flags;

	/// Type of mapping: Confidential or Shared.
	segment_type_t tpe;
} msg_mprotect_t;

/// Structure to perform a transition.
typedef struct {
	/// The args, will end up in r11 on x86.
	void *args;
} msg_switch_t;

/// Structure to set permissions, i.e., traps or cores.
typedef struct {
	// Core for the config.
	usize core;
	// Configuration type.
	usize idx;
	// Configuration values.
	usize value;
} msg_set_perm_t;

/// A message to create a pipe
typedef struct {
	/// The id for the pipe.
	usize id;
	/// The start phys_addr;
	usize phys_addr;
	/// The size.
	usize size;
	/// memory flags
	memory_access_right_t flags;
	/// The number of acquirable pipes.
	usize width;
} msg_create_pipe_t;

/// Information about the attestation buffer.
typedef struct {
    /// Virtual address of the start of the buffer.
    usize start;

    /// Size of the buffer.
    usize size;

    /// How many bytes were written by Tyche.
    usize written;
} attest_buffer_t;

// ———————————————————————————— Tyche IOCTL API ————————————————————————————— //
// @deprecated, use open.
#define TYCHE_GET_PHYSOFFSET _IOWR('a', 'c', msg_info_t *)
#define TYCHE_COMMIT _IOWR('a', 'd', void *)
#define TYCHE_MPROTECT _IOW('a', 'e', msg_mprotect_t *)
#define TYCHE_TRANSITION _IOR('a', 'f', msg_switch_t *)
#define TYCHE_DEBUG_ADDR _IOWR('a', 'h', msg_info_t *)
#define TYCHE_SET_DOMAIN_CORE_CONFIG _IOR('a', 'g', msg_set_perm_t *)
#define TYCHE_SET_DOMAIN_CONFIGURATION _IOR('a', 'i', msg_set_perm_t *)
#define TYCHE_ALLOC_CONTEXT _IOW('a', 'n', usize)
#define TYCHE_CREATE_PIPE _IOWR('a', 'o', msg_create_pipe_t)
#define TYCHE_ACQUIRE_PIPE _IOR('a', 'p', usize)
#define TYCHE_GET_ATTESTATION _IOWR('a', 'q', attest_buffer_t *)

#endif
