#ifndef __INCLUDE_TYCHE_CAPABILITIES_H__
#define __INCLUDE_TYCHE_CAPABILITIES_H__

#include "ecs.h"
#include "tyche_capabilities_types.h"
#include "tyche_register_map.h"

// ———————————————————————————————— Globals —————————————————————————————————
// //

extern domain_t local_domain;

// —————————————————————————————————— API ———————————————————————————————————
// //

/// Initialize the local domain.
/// This function enumerates the regions attributed to this domain and
/// populates the local_domain.
int init(capa_alloc_t allocator, capa_dealloc_t deallocator);

/// Creates a new domain.
/// Sets the result inside the provided id handle.
int create_domain(domain_id_t *id, int aliased);

/// Seal the domain.
/// This function first creates a channel for the child domain and then seals
/// it.
int seal_domain(domain_id_t id);

/// Duplicate capability.
int segment_region_capa(int is_shared, capability_t *capa,
			capability_t **to_send, capability_t **revoke,
			usize start, usize end, usize prot);

/// Grant a memory region.
/// Finds the correct capability and grants the region to the target domain.
int grant_region(domain_id_t id, paddr_t start, usize size,
		 memory_access_right_t access, usize alias);

/// Carve a memory region without sending it to anyone.
/// @warning: it removes the capabilities from the local domain,
/// Don't lose them!
int cut_region(paddr_t start, usize size, memory_access_right_t access,
	       capability_t **to_send, capability_t **revoke);

/// Duplicates the capability and creates a revocation handle for it.
/// @warning: removes the capabilities from the local domain so don't lose them.
int dup_region(capability_t *capa, capability_t **dup, capability_t **revoke);

/// Send a pre-computed capa to a domain.
/// This will free the capa in the capa engine and add the revoke to it.
/// Make sure none of these is inside a list.
int send_region(domain_id_t id, capability_t *capa, capability_t *revoke,
		usize send_access);

/// Share a memory region.
/// Finds the correct capability and shares the region with the target domain.
int share_region(domain_id_t id, paddr_t start, usize size,
		 memory_access_right_t access, usize alias);

/// Share a memory region that is aliased and repeats.
/// This leads to one physical page starting at start, mapped from alias to alias + size.
int share_repeat_region(domain_id_t id, paddr_t start, usize size,
			memory_access_right_t access, usize alias);

/// Revoke the memory region.
/// Start and end must match existing bounds on a capability.
int revoke_region(domain_id_t id, paddr_t start, paddr_t end);

/// Switch to the target domain.
/// If args is not null, registers will be dumped there upon return.
/// Fails if all transition handles are used.
/// TODO(aghosn) where is the core?
int switch_domain(domain_id_t id, usize exit_frame[TYCHE_EXIT_FRAME_SIZE]);

/// Delete a domain.
/// This function goes through all the capabilities in the domain and revokes
/// them.
int revoke_domain(domain_id_t id);

/// Delete a domain's memory region.
/// This function goes through the revocations and calls internal revoke.
int revoke_domain_regions(domain_id_t id);

/// Read all general purpose registers (minus rip and rsp)
int read_gp_domain(domain_id_t id, usize core, usize regs[TYCHE_GP_REGS_SIZE]);

/// Set configurations for the domain (traps, cores, switch type, perms).
/// The domain must not be sealed and values must be subsets of the parents.
int set_domain_configuration(domain_id_t id, tyche_configurations_t idx,
			     usize value);

/// Set values inside the target domain.
int set_domain_core_configuration(domain_id_t id, usize core, usize idx,
				  usize value);

/// Set `size` values in the target domain on core.
int write_fields(domain_id_t id, usize core, usize *fields, usize *values,
		 int size);

/// Allocate a core context for the domain.
int alloc_core_context(domain_id_t id, usize core);

/// Get values inside the target domain.
int get_domain_core_configuration(domain_id_t id, usize core, usize idx,
				  usize *value);
#endif
