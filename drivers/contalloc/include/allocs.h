#ifndef __SRC_ALLOCS_H__
#define __SRC_ALLOCS_H__

#include "color_bitmap.h"
#include <linux/fs.h>
#include <linux/mm_types.h>

#include "dll.h"
#include "common.h"
#define _IN_MODULE
#include "contalloc_driver.h"
#undef _IN_MODULE

// ————————————————————————————————— Types —————————————————————————————————— //

typedef struct file *driver_handle_t;

typedef struct {
	usize gpa;
	size_t size;
	uint64_t color_id;
	//start_hpa and end_hpa specify the gpa range on the host
	//that backs this memory, if we only consider pages with the
	//color from color_id
	uint64_t start_hpa;
	uint64_t end_hpa;
} alloc_fragment_t;
typedef struct mmem_t {
	/// Start of the virtual memory segment.
	usize start_gva;
	/// Corresponding start of the physical segment.
	usize start_gpa;
	usize size;

	//use mmem_t_add_fragment to manage these
	alloc_fragment_t *fragments;
	size_t fragment_count;
	size_t _fragment_capacity;

	color_bitmap_t color_bm;

	/// Segments are stored in a double linked list in the allocs driver
	dll_elem(struct mmem_t, list);
} mmem_t;

void mmem_t_init(mmem_t *mmem, size_t color_count);
void mmem_t_add_fragment(mmem_t *mmem, alloc_fragment_t fragment);
int mmem_t_pop_from_front(mmem_t *self, size_t remove_count);
void mmem_t_deepcopy(mmem_t *source, mmem_t *target);
void mmem_t_free(mmem_t mmem);

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
void contalloc_init_allocs(void);
/// Create a new alloc with handle.

// Creates a metadata entry for this handle which will be used to track all
// future allocations
int contalloc_create_alloc(driver_handle_t handle);

/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it
int contalloc_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma);
int contalloc_get_segment(driver_handle_t handle, uint64_t start_gva,
			  mmem_t *out_segment);

/// Returns the alloc's physoffset.
/// We expect the handle to be valid.
int driver_get_physoffset_alloc(cont_alloc_t *alloc, usize slot_id,
				usize *phys_offset);

/// Delete the allocation.
int contalloc_delete_alloc(cont_alloc_t *alloc);

int contalloc_open(struct inode *inode, struct file *file);
int contalloc_close(struct inode *inode, struct file *file);
int contalloc_mmap(struct file *, struct vm_area_struct *);

#endif /*__SRC_ALLOCS_H__*/
