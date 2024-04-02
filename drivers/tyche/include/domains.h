#ifndef __SRC_DOMAINS_H__
#define __SRC_DOMAINS_H__

#include "linux/rwsem.h"
#include <linux/fs.h>
#include <linux/mm_types.h>

#include "dll.h"
#include "tyche_api.h"
#include "tyche_capabilities_types.h"
#define _IN_MODULE
#include "tyche_driver.h"
#include "arch_cache.h"
#undef _IN_MODULE

// ————————————————————————————————— Types —————————————————————————————————— //

#define UNINIT_USIZE (~((usize)0))
#define UNINIT_DOM_ID (~((domain_id_t)0))

/// Internal state within the driver, used for domains and segments.
/// This mirrors whether the information has been sent to tyche or not.
typedef enum driver_state_t {
	DRIVER_NOT_COMMITED = 0,
	DRIVER_COMMITED = 1,
	DRIVER_DEAD = 2,
} driver_state_t;

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

	/// The offset at which the segment is mapped (gpa).
	usize alias;

	/// Segment state.
	driver_state_t state;

	/// Segments are stored in a double linked list.
	dll_elem(struct segment_t, list);
} segment_t;

#define ENTRIES_PER_DOMAIN (16)

/// Indicies in the domain config array.
typedef tyche_configurations_t driver_domain_config_t;

/// A domain's core context.
typedef struct context_t {
	/// Locking mechanism for the context.
	struct rw_semaphore rwlock;

	/// The context data.
	arch_cache_t cache;
} context_t;

/// Describes an domain.
typedef struct driver_domain_t {
	/// The creator task's pid.
	pid_t pid;

	/// The domain's handle within the driver.
	domain_handle_t handle;

	/// The domain's domain id.
	domain_id_t domain_id;

	/// The domain's state.
	driver_state_t state;

	/// The domain's configuration.
	usize configs[TYCHE_NR_CONFIGS];

	/// Cached contexts for domains.
	context_t *contexts[ENTRIES_PER_DOMAIN];

	/// The available raw memory segments.
	/// This is typically allocated during the mmap (from userspace),
	/// or taken from KVM (kvm_memory_regions).
	dll_list(segment_t, raw_segments);

	/// The initialized segments for the domain.
	/// The access rights have been set.
	dll_list(segment_t, segments);

	/// Domains are stored in a global list by the driver.
	dll_elem(struct driver_domain_t, list);

	/// R/W-lock: multiple readers when working on contexts, one writer when
	/// modifying the domain itself.
	struct rw_semaphore rwlock;
} driver_domain_t;

typedef struct driver_pipe_t {
	// The next available pipe id.
	usize id;
	// The phys start of the pipe.
	usize phys_start;
	// The size of the pipe;
	usize size;
	// This is stored in a list inside the global driver state.
	dll_elem(struct driver_pipe_t, list);

	/// The list of active regions to serve on acquire.
	dll_list(capability_t, actives);
	/// The list of revocations for the above region. Maintain order!
	dll_list(capability_t, revokes);
} driver_pipe_t;

// ———————————————————————————————— Helpers ————————————————————————————————— //

// Find a currently active domain from a file descriptor.
// This function acquires the state's readlock. It returns a locked
// domain (write lock if `write` is true, read lock otherwise).
driver_domain_t *find_domain(domain_handle_t handle, bool write);

// ——————————————————————————————— Functions ———————————————————————————————— //

/// Initializes the driver.
void driver_init_domains(void);

/// Initializes the capability library.
int driver_init_capabilities(void);

/// Create a new domain with handle.
/// If ptr is not null, it points to the newly created driver domain.
int driver_create_domain(domain_handle_t handle, driver_domain_t **ptr,
			 int aliased);
/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it until a domain claims
/// it.
/// @warning: expects the domain to be w-locked.
int driver_mmap_segment(driver_domain_t *domain, struct vm_area_struct *vma);

/// Add a raw memory segment to the domain.
/// @warning: expects the domain to be w-locked.
int driver_add_raw_segment(driver_domain_t *dom, usize va, usize pa,
			   usize size);

/// Returns the domain's physoffset.
/// We expect the handle to be valid, and the virtaddr to exist in segments.
/// @warning: expects the domain to be R-locked.
int driver_get_physoffset_domain(driver_domain_t *domain, usize slot_id,
				 usize *phys_offset);

/// Sets up access rights and conf|share for the segment.
/// @warning: expects the domain to be W-locked.
int driver_mprotect_domain(driver_domain_t *domain, usize vstart, usize size,
			   memory_access_right_t flags, segment_type_t tpe,
			   usize alias);

/// Sets the domain's configuration (cores, traps, switch type).
/// @warning: expects the domain to be W-locked.
int driver_set_domain_configuration(driver_domain_t *domain,
				    driver_domain_config_t tpe, usize value);

/// Sets a self configuration for the core.
int driver_set_self_core_config(usize field, usize value);

/// Expose the configuration of fields (write).
/// @warning: expects the domain to be R-locked and will W-lock the context.
int driver_set_domain_core_config(driver_domain_t *dom, usize core, usize idx,
				  usize value);

/// Allocate a core context for the specified core.
/// @warning: expects the domain to be W-locked.
int driver_alloc_core_context(driver_domain_t *dom, usize core);

/// Expose the configuration of fields (read).
/// @warning: expects a R-lock on the domain, will acquire a R-lock on the core.
/// If the value is not in the cache, it will acquire a W-lock on the core.
int driver_get_domain_core_config(driver_domain_t *dom, usize core, usize idx,
				  usize *value);

/// Performs the calls to tyche monitor for the selected regions.
/// @warning: requires a W-lock on the domain.
int driver_commit_regions(driver_domain_t *dom);

/// Commit the configuration, i.e., call the capabilities.
/// @warning: requires a W-lock on the domain.
int driver_commit_domain_configuration(driver_domain_t *dom,
				       driver_domain_config_t idx);

/// Commits the domain. This is where the capability operations are mostly
/// done.
/// @warning: requires a write lock on the domain.
int driver_commit_domain(driver_domain_t *domain, int full);

/// Implements the transition into a domain on specified core.
/// @warning: requires a R-lock on the domain. Will acquire a W-lock on the core
/// we switch to.
int driver_switch_domain(driver_domain_t *domain, usize core);

/// Delete the domain and revoke the capabilities.
/// @warning: requires a W-lock on the domain.
int driver_delete_domain(driver_domain_t *domain);

/// Delete the domain's regions.
/// @warning: requires a W-lock on the domain.
int driver_delete_domain_regions(driver_domain_t *dom);

/// Create a pipe.
/// The pipe starts at phys_addr for size bytes, will be carved with flags
/// and duplicated width times.
/// If everything goes well, the result pipe id is put inside pipe_id.
int driver_create_pipe(usize *pipe_id, usize phys_addr, usize size,
		       memory_access_right_t flags, usize width);

/// Acquires an end of pipe and adds it to the domain.
/// @warning: requires a W-lock on the domain.
int driver_acquire_pipe(driver_domain_t *domain, usize pipe);

/// Find the pipe_id from a physical address.
int driver_find_pipe_from_hpa(usize *pipe_id, usize addr, usize size);

/// Request tyche to serialize an atestation of the current state of the system
/// into the provided buffer.
int driver_serialize_attestation(char *addr, usize size, usize *written);
#endif /*__SRC_DOMAINS_H__*/
