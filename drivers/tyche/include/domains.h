#ifndef __SRC_DOMAINS_H__
#define __SRC_DOMAINS_H__

#include <linux/fs.h>
#include <linux/mm_types.h>

#include "dll.h"
#include "tyche_capabilities_types.h"
#define _IN_MODULE
#include "tyche_driver.h"
#undef _IN_MODULE

// ————————————————————————————————— Types —————————————————————————————————— //

#define UNINIT_USIZE (~((usize)0))
#define UNINIT_DOM_ID (~((domain_id_t)0))

/// Describes an domain's memory segment in user process address space.
typedef struct segment_t {
	/// Start of the virtual memory segment.
	usize va;

	/// Corresponding start of the physical segment.
	usize pa;

	/// Size of the memory segment.
	usize size;

	/// Protection flags.
	memory_access_right_t flags;

	/// Type for the region: {Shared|Confidential}.
	segment_type_t tpe;

	/// Segments are stored in a double linked list.
	dll_elem(struct segment_t, list);
} segment_t;

/// An entry point on a core for the domain.
typedef struct entry_t {
	usize cr3;
	usize rip;
	usize rsp;
} entry_t;

/// All entry points for the domain.
typedef struct entries_t {
	/// One entry per core, total number of entries.
	size_t size;
	/// The entries dynamically allocated.
	entry_t *entries;
} entries_t;

/// The state of the domain.
typedef enum domain_state_t {
	DOMAIN_NOT_COMMITED = 0,
	DOMAIN_COMMITED = 1,
	DOMAIN_DEAD = 2,
} domain_state_t;

/// Describes an domain.
typedef struct driver_domain_t {
	/// The creator task's pid.
	pid_t pid;

	/// The domain's handle within the driver.
	domain_handle_t handle;

	/// The domain's domain id.
	domain_id_t domain_id;

	/// The domain's state.
	domain_state_t state;

	/// The domain's traps.
	usize traps;

	/// The domain's core map.
	usize cores;

	/// The domain's permission.
	usize perm;

	/// The domain's switch value.
	usize switch_type;

	/// The domain's entry points per core.
	entries_t entries;

	/// The available raw memory segments.
	/// This is typically allocated during the mmap (from userspace),
	/// or taken from KVM (kvm_memory_regions).
	dll_list(segment_t, raw_segments);

	/// The initialized segments for the domain.
	/// The access rights have been set.
	dll_list(segment_t, segments);

	/// Domains are stored in a global list by the driver.
	dll_elem(struct driver_domain_t, list);
} driver_domain_t;

// ———————————————————————————————— Helpers ————————————————————————————————— //

// Find a currently active domain from a file descriptor.
driver_domain_t *find_domain(domain_handle_t handle);

// ——————————————————————————————— Functions ———————————————————————————————— //

/// Initializes the driver.
void driver_init_domains(void);
/// Initializes the capability library.
int driver_init_capabilities(void);
/// Create a new domain with handle.
/// If ptr is not null, it points to the newly created driver domain.
int driver_create_domain(domain_handle_t handle, driver_domain_t **ptr);
/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it until a domain claims it.
int driver_mmap_segment(driver_domain_t *domain, struct vm_area_struct *vma);
/// Add a raw memory segment to the domain.
int driver_add_raw_segment(driver_domain_t *dom, usize va, usize pa,
			   usize size);
/// Returns the domain's physoffset.
/// We expect the handle to be valid, and the virtaddr to exist in segments.
int driver_get_physoffset_domain(driver_domain_t *domain, usize *phys_offset);
/// Sets up access rights and conf|share for the segment.
int driver_mprotect_domain(driver_domain_t *domain, usize vstart, usize size,
			   memory_access_right_t flags, segment_type_t tpe);
/// Register the trap bitmap for the domain.
int driver_set_traps(driver_domain_t *domain, usize traps);
/// Register the core map for the domain.
int driver_set_cores(driver_domain_t *domain, usize core_map);
/// Register the perm for the domain.
int driver_set_perm(driver_domain_t *domain, usize perm);
/// Register the switch_type for the domain.
int driver_set_switch(driver_domain_t *domain, usize sw);
/// Set the entry point on a core.
int driver_set_entry_on_core(driver_domain_t *domain, usize core, usize cr3,
			     usize rip, usize rsp);
/// Commits the domain. This is where the capability operations are done.
int driver_commit_domain(driver_domain_t *domain);
/// Implements the transition into a domain.
int driver_switch_domain(driver_domain_t *domain, void *args);
/// Delete the domain and revoke the capabilities.
int driver_delete_domain(driver_domain_t *domain);
#endif /*__SRC_DOMAINS_H__*/
