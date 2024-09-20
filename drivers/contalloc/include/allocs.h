#ifndef __SRC_ALLOCS_H__
#define __SRC_ALLOCS_H__

#include <linux/fs.h>
#include <linux/mm_types.h>

#include "dll.h"
#include "common.h"
#define _IN_MODULE
#include "contalloc_driver.h"
#include "domains.h"
#undef _IN_MODULE

// ————————————————————————————————— Types —————————————————————————————————— //

typedef struct file *driver_handle_t;

typedef segment_t mmem_t;

/*typedef struct mmem_t {
	/// Start of the virtual memory segment.
	usize va;

	/// Corresponding start of the physical segment.
	usize pa;

	/// Size of the memory segment.
	usize size;

	/// Segments are stored in a double linked list.
	dll_elem(struct mmem_t, list);
} mmem_t;*/

/// Describes a continous allocation.
typedef struct cont_alloc_t {
	/// The creator task's pid.
	pid_t pid;

	/// The driver file descriptor associated with this allocation.
	driver_handle_t handle;

	/// The available raw memory segments.
	/// This is typically allocated during the mmap (from userspace),
	segment_list_t raw_segments;

	/// Allocations are stored in a global list by the driver.
	dll_elem(struct cont_alloc_t, list);
} cont_alloc_t;

// ———————————————————————————————— Helpers ————————————————————————————————— //

// Find a currently active alloc from a file descriptor.
cont_alloc_t *find_alloc(driver_handle_t);

// ——————————————————————————————— Functions ———————————————————————————————— //

/// Initializes the driver.
void contalloc_init_allocs(void);
/// Create a new alloc with handle.
int contalloc_create_alloc(driver_handle_t handle);
/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it
int contalloc_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma);
/// Returns the alloc's physoffset.
int contalloc_get_physoffset_alloc(cont_alloc_t *alloc, usize vaddr,
				   usize *phys_offset);
/// Delete the allocation.
int contalloc_delete_alloc(cont_alloc_t *alloc);

/// Register an mmap from linux.
int contalloc_register_mmap(cont_alloc_t *alloc, usize vaddr, usize size);
#endif /*__SRC_ALLOCS_H__*/
