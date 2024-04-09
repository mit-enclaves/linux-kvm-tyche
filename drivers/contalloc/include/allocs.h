#ifndef __SRC_ALLOCS_H__
#define __SRC_ALLOCS_H__

#include <linux/fs.h>
#include <linux/mm_types.h>

#include "dll.h"
#include "common.h"
#define _IN_MODULE
#include "contalloc_driver.h"
#undef _IN_MODULE

// ————————————————————————————————— Types —————————————————————————————————— //

typedef struct file *driver_handle_t;

typedef struct mmem_t {
	/// Start of the virtual memory segment.
	usize va;

	/// Corresponding start of the physical segment.
	usize pa;

	/// Size of the memory segment.
	usize size;

	/// Segments are stored in a double linked list.
	dll_elem(struct mmem_t, list);
} mmem_t;

/// Describes a continous allocation.
typedef struct cont_alloc_t {
	/// The creator task's pid.
	pid_t pid;

	/// The driver file descriptor associated with this allocation.
	driver_handle_t handle;

	/// The available raw memory segments.
	/// This is typically allocated during the mmap (from userspace),
	dll_list(mmem_t, raw_segments);

	/// Allocations are stored in a global list by the driver.
	dll_elem(struct cont_alloc_t, list);
} cont_alloc_t;

// ———————————————————————————————— Helpers ————————————————————————————————— //

// Find a currently active alloc from a file descriptor.
cont_alloc_t *find_alloc(driver_handle_t);

// ——————————————————————————————— Functions ———————————————————————————————— //

/// Initializes the driver.
void driver_init_allocs(void);
/// Create a new alloc with handle.
int driver_create_alloc(driver_handle_t handle);
/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it
int driver_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma);
/// Returns the alloc's physoffset.
/// We expect the handle to be valid.
int driver_get_physoffset_alloc(cont_alloc_t *alloc, usize slot_id,
				usize *phys_offset);
/// Delete the allocation.
int driver_delete_alloc(cont_alloc_t *alloc);
#endif /*__SRC_ALLOCS_H__*/
