#include "dll.h"
#include "tyche_api.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"
#define TYCHE_DEBUG 1
#include "common.h"
#include "common_log.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

domain_t local_domain;

// ———————————————————————— Private helper functions ———————————————————————— //

void local_memcpy(void *dest, void *src, unsigned long n) {
  unsigned long i = 0;
  char *csrc = (char *)src;
  char *cdest = (char *)dest;
  for (i = 0; i < n; i++) {
    cdest[i] = csrc[i];
  }
}

void local_memset(void *dest, unsigned long n) {
  unsigned long i = 0;
  char *cdest = (char *)dest;
  for (i = 0; i < n; i++) {
    cdest[i] = 0;
  }
}

child_domain_t* find_child(domain_id_t id)
{
  child_domain_t *child = NULL;
  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }
  return child;
}

int has_access_rights(memory_access_right_t orig, memory_access_right_t dest)
{
  return (orig & dest) == dest;
}

// —————————————————————————————— Public APIs ——————————————————————————————— //

int init(capa_alloc_t allocator, capa_dealloc_t deallocator) {
  capa_index_t next = 0;
  if (allocator == 0 || deallocator == 0) {
    goto fail;
  }
  // Set the local domain's functions.
  local_domain.alloc = allocator;
  local_domain.dealloc = deallocator;
  dll_init_list(&(local_domain.capabilities));
  dll_init_list(&(local_domain.children));

  // Start enumerating the domain's capabilities.
  while (1) {
    capability_t tmp_capa;
    capability_t *capa = NULL;
    if (enumerate_capa(next, &next, &tmp_capa) != SUCCESS || next == 0) {
      // Failed to read or no more capa
      break;
    }

    capa = (capability_t *)(local_domain.alloc(sizeof(capability_t)));
    if (capa == NULL) {
      ERROR("Unable to allocate a capability!\n");
      goto failure;
    }
    // Copy the capability into the dynamically allocated one.
    local_memcpy(capa, &tmp_capa, sizeof(capability_t));
    dll_init_elem(capa, list);

    // Add the capability to the list.
    dll_add(&(local_domain.capabilities), capa, list);
  }

  DEBUG("success");
  return SUCCESS;
failure:
  while (!dll_is_empty(&local_domain.capabilities)) {
    capability_t *capa = local_domain.capabilities.head;
    dll_remove(&(local_domain.capabilities), capa, list);
    local_domain.dealloc((void *)capa);
  }
fail:
  return FAILURE;
}

int create_domain(domain_id_t *id, int aliased) {
  capa_index_t child_idx = -1;
  capability_t *child_capa = NULL;
  child_domain_t *child = NULL;

  DEBUG("start");
  // Initialization was not performed correctly.
  if (id == NULL) {
    ERROR("id null.");
    goto fail;
  }

  // Perform allocations.
  child = (child_domain_t *)local_domain.alloc(sizeof(child_domain_t));
  if (child == NULL) {
    ERROR("Failed to allocate child.");
    goto fail;
  }
  child_capa = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (child_capa == NULL) {
    ERROR("Failed to allocate child_capa.");
    goto fail_child;
  }

  // Create the domain.
  if (tyche_create_domain(&child_idx, aliased) != SUCCESS) {
    ERROR("Failed to create domain.");
    goto fail_child_capa;
  }

  // Populate the capability.
  if (enumerate_capa(child_idx, NULL, child_capa) != SUCCESS) {
    ERROR("Failed to enumerate the newly created child.");
    goto fail_child_capa;
  }

  // Check that the child capa is a management one.
  if (child_capa->capa_type != Management ||
      child_capa->info.management.status != Unsealed) {
    ERROR("The created domain capa is invalid: type: 0x%x status 0x%x",
        child_capa->capa_type,
        child_capa->info.management.status);
    goto fail_child_capa;
  }

  // Initialize the other capa fields.
  dll_init_elem(child_capa, list); 

  // Initialize the child domain.
  child->id = local_domain.id_counter++;
  child->management = child_capa;
  dll_init_list(&(child->revocations));
  dll_init_list(&(child->transitions));
  dll_init_elem(child, list);

  // Add the child to the local_domain.
  dll_add(&(local_domain.children), child, list);

  // All done!
  *id = child->id;
  DEBUG("Success");
  return SUCCESS;

  // Failure paths.
fail_child_capa:
  local_domain.dealloc(child_capa);
fail_child:
  local_domain.dealloc(child);
fail:
  return FAILURE;
}

int get_domain_capa(domain_id_t id, capa_index_t* capa)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }
  if (capa == NULL) {
    ERROR("Supplied capability is null.");
    goto failure;
  }
  *capa = child->management->local_id;
  return SUCCESS;
failure:
  return FAILURE;
}

int set_domain_configuration(domain_id_t id, tyche_configurations_t idx, usize value)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }
  if (tyche_set_domain_config(child->management->local_id, idx, value) != SUCCESS) {
    ERROR("Unable to set config %d for dom %lld", idx, id);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int set_domain_core_configuration(domain_id_t id, usize core, usize idx, usize value)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }
  if (tyche_set_domain_core_config(child->management->local_id, core, idx, value) != SUCCESS) {
    ERROR("Unable to set core config %lld for dom %llx", idx, id);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int write_fields(domain_id_t id, usize core, usize* fields, usize* values, int size) {
  child_domain_t *child = find_child(id);
  if (child == NULL || size > 7) {
    ERROR("Child not found or size too big.");
    goto failure;
  }
  if (tyche_write_fields(child->management->local_id, core, fields, values, size) != SUCCESS) {
    ERROR("Unable to write the fields with tyche.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int alloc_core_context(domain_id_t id, usize core) {
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }

  if (tyche_alloc_core_context(child->management->local_id, core) != SUCCESS) {
    ERROR("Unable to allocate the core context.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int get_domain_core_configuration(domain_id_t id, usize core, usize idx, usize *value) {
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }
  if (value == NULL) {
    ERROR("Value provided is null.");
    goto failure;
  }
  if (tyche_get_domain_core_config(child->management->local_id, core, idx, value) != SUCCESS) {
    ERROR("Unable to get core config %lld for dom %lld", idx, id);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int seal_domain(domain_id_t id) {
  child_domain_t *child = NULL;
  capability_t *transition = NULL;
  transition_t *trans_wrapper = NULL;

  DEBUG("start");
  // Find the target domain.
  child = find_child(id); 

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }

  transition = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (transition == NULL) {
    ERROR("Could not allocate transition capa.");
    goto failure;
  }

  trans_wrapper = (transition_t *)local_domain.alloc(sizeof(transition_t));
  if (trans_wrapper == NULL) {
    ERROR("Unable to allocate transition_t wrapper");
    goto failure_transition;
  }

  // Create the transfer.
  if (child->management == NULL) {
    ERROR("The child's management is null");
    goto failure_dealloc;
  }
  if (child->management->capa_type != Management ||
      child->management->info.management.status != Unsealed ) {
    ERROR("we do not have a valid unsealed capa.");
    ERROR("management capa: type: 0x%x  -- status 0x%x",
        child->management->info.management.status,
        child->management->info.management.status);
    goto failure_dealloc;
  }

  if (tyche_seal(&(transition->local_id), child->management->local_id) != SUCCESS) {
    ERROR("Unable to create a channel.");
    goto failure_dealloc;
  }

  // Enumerate the transition capability.
  if (enumerate_capa(transition->local_id, NULL, transition) != SUCCESS) {
    ERROR("Unable to read the transition capability.");
    goto failure_dealloc;
  }

  // Update the management capability.
  if (enumerate_capa(child->management->local_id, NULL, child->management) != SUCCESS) {
    ERROR("Unable to update the management capa.");
    goto failure_dealloc;
  }

  // Initialize the transition wrapper.
  trans_wrapper->transition = transition;
  trans_wrapper->lock = TRANSITION_UNLOCKED;
  dll_init_elem(trans_wrapper, list);

  // Add the transition wrapper to the child.
  dll_add(&(child->transitions), trans_wrapper, list);

  // All done !
  DEBUG("Success");
  return SUCCESS;
failure_dealloc:
  local_domain.dealloc(trans_wrapper);
failure_transition:
  local_domain.dealloc(transition);
failure:
  return FAILURE;
}


int segment_region_capa(
    int is_shared,
    capability_t *capa,
    capability_t **to_send,
    capability_t **revoke,
    usize start,
    usize end,
    usize prot) {
  if (to_send == NULL || revoke == NULL || capa == NULL) {
    goto failure;
  }

  // Attempt to allocate the two capabilities.
  *to_send = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (*to_send == NULL) {
    ERROR("to_send alloc failed.");
    goto failure;
  }
  *revoke = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (*revoke == NULL) {
    ERROR("Revoke alloc failed.");
    goto fail_to_send;
  }

  // Call duplicate.
  if (tyche_segment_region(
        (usize) (is_shared != 0),
        capa->local_id,
        &((*to_send)->local_id),
        &((*revoke)->local_id),
        start, end, prot) != SUCCESS) {
    ERROR("Duplicate rejected.");
    goto fail_revoke;
  }

  // Update the capability.
  if (enumerate_capa(capa->local_id, NULL, capa) != SUCCESS) {
    ERROR("We failed to enumerate the root of a duplicate!");
    goto fail_revoke;
  }

  // Initialize the to_send.
  if (enumerate_capa((*to_send)->local_id, NULL, *to_send) != SUCCESS) {
    ERROR("We failed to enumerate the to_send of duplicate!");
    goto fail_revoke;
  }
  dll_init_elem((*to_send), list);
  dll_add(&(local_domain.capabilities), (*to_send), list);

  // Initialize the revoke.
  if (enumerate_capa((*revoke)->local_id, NULL, (*revoke)) != SUCCESS) {
    ERROR("We failed to enumerate the revoke!");
    goto fail_revoke;
  }
  dll_init_elem((*revoke), list);
  dll_add(&(local_domain.capabilities), (*revoke), list);

  // All done!
  return SUCCESS;

  // Failure paths.
fail_revoke:
  local_domain.dealloc(*revoke);
fail_to_send:
  local_domain.dealloc(*to_send);
failure:
  return FAILURE;
}

int cut_region(paddr_t start, usize size, memory_access_right_t access,
    capability_t **to_send, capability_t **revoke) {
  capability_t *capa = NULL;
  usize end = start + size;
  if (to_send == NULL || revoke == NULL) {
    goto failure;
  }
  // Now attempt to find the capability.
  dll_foreach(&(local_domain.capabilities), capa, list) {
    if (capa->capa_type != Region || (capa->info.region.flags & MEM_ACTIVE) == 0) {
      continue;
    }
    if ((dll_contains(
            capa->info.region.start,
            capa->info.region.end, start)) &&
        (capa->info.region.start <= end && capa->info.region.end >= end)
        && has_access_rights(capa->info.region.flags, access)) {
      // Found the capability.
      break;
    }
  }

  // We were not able to find the capability.
  if (capa == NULL) {
    LOG("The access rights we want: %x", access);
    ERROR("Unable to find the containing capa: %llx -- %llx",
        start, end);
    /*asm volatile (
      "movq $11, %%rax\n\t"
      "vmcall\n\t"
      :
      :
      : "rax", "memory"
        );*/
    goto failure;
  }

  //@aghosn: this is the new capa interface for regions.
  if (segment_region_capa(0, capa, to_send, revoke, start, end, access >> 2) != SUCCESS) {
    ERROR("Unable to segment the region !");
    goto failure;
  }
  dll_remove(&(local_domain.capabilities), *to_send, list);
  dll_remove(&(local_domain.capabilities), *revoke, list);
  return SUCCESS;
failure:
  return FAILURE;
}

int dup_region(capability_t *capa, capability_t **dup, capability_t **revoke) {
  if (dup == NULL || revoke == NULL || capa == NULL) {
    goto failure;
  }
  if (capa->capa_type != Region) {
    ERROR("The capa is not a region");
    goto failure;
  }
  if (segment_region_capa(1, capa, dup, revoke, capa->info.region.start,
        capa->info.region.end, capa->info.region.flags >> 2) != SUCCESS) {
    ERROR("Unable to duplicate the capability");
    goto failure;
  }
  // Remove both from the local domain.
  dll_remove(&(local_domain.capabilities), *dup, list);
  dll_remove(&(local_domain.capabilities), *revoke, list);
  return SUCCESS;
failure:
  return FAILURE;
}

int send_region(domain_id_t id, capability_t *capa, capability_t *revoke,
    usize send_access) {
  child_domain_t *child = NULL;
  if (capa == NULL || revoke == NULL) {
    goto failure;
  }
  child = find_child(id);
  if (child == NULL) {
    ERROR("Unable to find the child");
    goto failure;
  }
  if (tyche_send_aliased(child->management->local_id, capa->local_id,
      0, capa->info.region.start,
      capa->info.region.end - capa->info.region.start,
      send_access >> 2) != SUCCESS) {
      ERROR("Unable to send an aliased capability!");
      goto failure;
  }
  revoke->info.revoke_region.alias_start = capa->info.region.start;
  revoke->info.revoke_region.alias_size = capa->info.region.end - capa->info.region.start;
  revoke->info.revoke_region.is_repeat = 0;
  dll_add(&(child->revocations), revoke, list);
  local_domain.dealloc(capa);
  return SUCCESS;
failure:
  return FAILURE;
}

int internal_carve_region(domain_id_t id, paddr_t start, usize size,
    memory_access_right_t access, int is_shared, int is_repeat,
     usize alias) {
  child_domain_t *child = NULL;
  capability_t *capa = NULL;
  capability_t* to_send = NULL;
  capability_t* revoke = NULL;
  memory_access_right_t basic_access = (access) & MEM_ACCESS_RIGHT_MASK_SEWRCA;
  memory_access_right_t send_access = (access) & MEM_ACCESS_RIGHT_MASK_VCH;
  usize aliased_start = (alias == NO_ALIAS)? start : alias;
  paddr_t end = (!is_repeat)? start + size : start + 0x1000;
  if ((basic_access | send_access) != access) {
    ERROR("Problem partitioning access right flags. Expected %x, got: %x",
        access, (basic_access | send_access));
    goto failure;
  }

  // Quick checks.
  if (start >= end) {
    ERROR("Start is greater or equal to end.\n");
    goto failure;
  }

  // Find the target domain.
  child = find_child(id); 

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }

  // Now attempt to find the capability.
  dll_foreach(&(local_domain.capabilities), capa, list) {
    if (capa->capa_type != Region || (capa->info.region.flags & MEM_ACTIVE) == 0) {
      continue;
    }
    if ((dll_contains(
            capa->info.region.start,
            capa->info.region.end, start)) &&
        (capa->info.region.start <= end && capa->info.region.end >= end)
        && has_access_rights(capa->info.region.flags, basic_access)) {
      // Found the capability.
      break;
    }
  }

  // We were not able to find the capability.
  if (capa == NULL) {
    LOG("The access rights we want: %x", access);
    ERROR("Unable to find the containing capa: %llx -- %llx | repeat: %d.",
        start, end, is_repeat);
    /*asm volatile (
      "movq $11, %%rax\n\t"
      "vmcall\n\t"
      :
      :
      : "rax", "memory"
        );*/
    goto failure;
  }

  //@aghosn: this is the new capa interface for regions.
  if (segment_region_capa(is_shared, capa, &to_send, &revoke, start, end, basic_access >> 2) != SUCCESS) {
    ERROR("Unable to segment the region !");
    goto failure;
  }
  if (tyche_send_aliased(child->management->local_id, to_send->local_id,
      is_repeat, aliased_start, size, send_access >> 2) != SUCCESS) {
      ERROR("Unable to send an aliased capability!");
      goto failure;
  }
  // Set the revocation information on the capability.
  // This is useful to maintain a coherent remapper.
  revoke->info.revoke_region.alias_start = aliased_start;
  revoke->info.revoke_region.alias_size = size; 
  revoke->info.revoke_region.is_repeat = is_repeat;
  // Sort things out in the different lists.
  dll_remove(&(local_domain.capabilities), to_send, list);
  dll_remove(&(local_domain.capabilities), revoke, list);
  dll_add(&(child->revocations), revoke, list);
  local_domain.dealloc(to_send);
  return SUCCESS;
failure:
  return FAILURE;
}

int grant_region(domain_id_t id, paddr_t start, usize size,
                 memory_access_right_t access, usize alias)
{
  return internal_carve_region(id, start, size, access, 0, 0, alias);
} 

int share_region(domain_id_t id, paddr_t start, usize size,
                 memory_access_right_t access, usize alias) {
  return internal_carve_region(id, start, size, access, 1, 0, alias);
} 

int share_repeat_region(domain_id_t id, paddr_t start, usize size,
    memory_access_right_t access, usize alias)
{
  if(alias == NO_ALIAS) {
    ERROR("Called share_repeat_region with no alias");
    return FAILURE;
  }
  return internal_carve_region(id, start, size, access, 1, 1, alias);
}

// @warning the handle should be deallocated by the caller!!!!
int internal_revoke(child_domain_t *child, capability_t *capa) {
  if (child == NULL || capa == NULL) {
    ERROR("null args.");
    goto failure;
  }

  if (capa->capa_type != RegionRevoke) {
    ERROR("Supplied capability is not a revocation");
    goto failure;
  }

  /*
  if (tyche_revoke(capa->local_id) != SUCCESS) {
    goto failure;
  }
  */
  if (tyche_revoke_region(capa->local_id, child->management->local_id,
        capa->info.revoke_region.alias_start,
        capa->info.revoke_region.alias_size) != SUCCESS) {
    ERROR("Unable to revoke the region!");
    goto failure;
  }

  // Remove the capability from the child.
  dll_remove(&(child->revocations), capa, list);

  // All done!
  DEBUG("success");
  return SUCCESS;
failure:
  ERROR("failure");
  return FAILURE;
}

int revoke_region(domain_id_t id, paddr_t start, paddr_t end) {
  child_domain_t *child = NULL;
  capability_t *capa = NULL;

  DEBUG("start");
  // Find the target domain.
  child = find_child(id); 

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("child not found.");
    goto failure;
  }

  // Try to find the region.
  dll_foreach(&(child->revocations), capa, list) {
    if (capa->capa_type == Region && capa->info.region.start == start &&
        capa->info.region.end == end) {
      // Found it!
      break;
    }
  }
  if (capa == NULL) {
    ERROR("Error[revoke_region]: unable to find region to revoke.");
    goto failure;
  }
  if (internal_revoke(child, capa) != SUCCESS) {
    goto failure;
  }
  // Deallocate the capa.
  local_domain.dealloc(capa);
  DEBUG("success");
  return SUCCESS;
failure:
  ERROR("failure");
  return FAILURE;
}

int read_gp_domain(domain_id_t id, usize core, usize regs[TYCHE_GP_REGS_SIZE]) {
  child_domain_t *child = NULL; 
  child = find_child(id);
  if (child == NULL || regs == NULL) {
    ERROR("Child is null or regs is null.");
    goto failure;
  }
  if (tyche_read_gp_registers(child->management->local_id, core, regs) != SUCCESS) {
    ERROR("Failed to read gp registers from tyche.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

// TODO nothing thread safe in this implementation for the moment.
int switch_domain(domain_id_t id, usize delta, usize exit_frame[TYCHE_EXIT_FRAME_SIZE]) {
  child_domain_t *child = NULL;
  transition_t *wrapper = NULL;
  DEBUG("start");

  if (exit_frame == NULL) {
    ERROR("Exit frame is null.");
    goto failure;
  }

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("child not found.");
    goto failure;
  }

  // Acquire a transition handle.
  dll_foreach(&(child->transitions), wrapper, list) {
    if (wrapper->lock == TRANSITION_UNLOCKED) {
      wrapper->lock = TRANSITION_LOCKED;
      break;
    } else if (wrapper->lock != TRANSITION_LOCKED) {
      ERROR("There is an invalid lock value %d (%p) (child: %p)", wrapper->lock,
            (void *)wrapper, (void *)child);
      goto failure;
    }
  }
  if (wrapper == NULL) {
    ERROR("Unable to find a transition handle!");
    goto failure;
  }
  DEBUG("Found a handle for domain %lld, id %lld", id,
        wrapper->transition->local_id);

  //TODO remove the tyche_write_gp_registers.
  /*if (args != NULL && tyche_write_gp_registers(child->management->local_id, args) != SUCCESS) {
    ERROR("failed to write all the registers.");
    goto failure;
  }*/
  if (tyche_switch(&(wrapper->transition->local_id), delta, exit_frame) !=
      SUCCESS) {
    DEBUG("failed to perform a switch on capa %lld",
          wrapper->transition->local_id);
    goto failure;
  }
  DEBUG("[switch_domain] Came back from the switch");
  //TODO(aghosn) remove this from capabilities.
  /*if (args != NULL && tyche_read_gp_registers(child->management->local_id, args) != SUCCESS) {
    ERROR("Unable to read gp registers.");
    goto failure;
  }*/
  // We are back from the switch, unlock the wrapper.
  wrapper->lock = TRANSITION_UNLOCKED;
  return SUCCESS;
failure:
  return FAILURE;
}

//TODO revoke domain is probably gonna be shit.
int revoke_domain(domain_id_t id) {
  child_domain_t *child = NULL;
  capability_t *capa = NULL;
  transition_t *wrapper = NULL;

  DEBUG("start");

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("unable to find the child.");
    goto failure;
  }

  // First go through all the revocations.
  while (!dll_is_empty(&(child->revocations))) {
    capa = child->revocations.head;

    if (internal_revoke(child, capa) != SUCCESS) {
      ERROR("unable to revoke a capability.");
      goto failure;
    }
    local_domain.dealloc(capa);
  }
  // Take care of the transitions + manipulate.
  // No need to call revoke, they should be handled by the cascading revocation.
  while (!dll_is_empty(&(child->transitions))) {
    wrapper = child->transitions.head;
    capa = wrapper->transition;
    dll_remove(&(child->transitions), wrapper, list);
    local_domain.dealloc(capa);
    local_domain.dealloc(wrapper);
  }

  // Kill the domain.
  if (tyche_revoke(child->management->local_id) != SUCCESS) {
    goto failure;
  }
  local_domain.dealloc(child->management);

  // Dealloc the domain.
  dll_remove(&(local_domain.children), child, list);
  local_domain.dealloc(child);

  DEBUG("[revoke_domain] success");
  return SUCCESS;
failure:
  ERROR("[revoke_domain] failure");
  return FAILURE;
}


int revoke_domain_regions(domain_id_t id)
{
  child_domain_t *child = find_child(id);
  capability_t *capa = NULL;

  if (child == NULL) {
    ERROR("Unable to find child with id %lld\n", id);
    goto failure;
  }

  // First go through all the revocations.
  while (!dll_is_empty(&(child->revocations))) {
    capa = child->revocations.head;
    //ERROR("revoke domain regions of type %d\n", capa->capa_type);
    if (internal_revoke(child, capa) != SUCCESS) {
      ERROR("unable to revoke a capability.");
      goto failure;
    }
    // Dealloc the structure.
    local_domain.dealloc(capa);
  }
  return SUCCESS;
failure:
  return FAILURE;
}
