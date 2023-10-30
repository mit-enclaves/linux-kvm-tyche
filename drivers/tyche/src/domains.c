#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <asm/io.h>
#include <linux/fs.h>

#include "common.h"
#include "domains.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

static dll_list(driver_domain_t, domains);

// ———————————————————————————— Helper Functions ———————————————————————————— //

driver_domain_t* find_domain(domain_handle_t handle)
{
  driver_domain_t* dom = NULL;
  dll_foreach((&domains), dom, list) {
    if (dom->handle == handle) {
      break;
    }
  }
  if (dom == NULL) {
    goto failure;
  }
  if (dom->pid != current->pid) {
    ERROR("Attempt to access dom %p from wrong pid", handle);
    ERROR("Expected pid: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  return dom;
failure:
  return NULL;
}


// ——————————————————————————————— Functions ———————————————————————————————— //

void driver_init_domains(void)
{
  dll_init_list((&domains));
  driver_init_capabilities();
}


int driver_create_domain(domain_handle_t handle, driver_domain_t** ptr, int aliased)
{
  driver_domain_t* dom = NULL;
  // This function can be called from the kvm backend as well.
  // In such cases, the domain handle will be null.
  dom = (handle != NULL)? find_domain(handle) : NULL;
  if (dom != NULL) {
    ERROR("The domain with handle %p already exists.", handle);
    goto failure;
  }
  dom = kmalloc(sizeof(driver_domain_t), GFP_KERNEL);
  if (dom == NULL) {
    ERROR("Failed to allocate a new driver_domain_t structure.");
    goto failure;
  }
  memset(dom, 0, sizeof(driver_domain_t));
  // Set up the structure.
  dom->pid = current->pid;
  dom->handle = handle;
  dom->domain_id = UNINIT_DOM_ID;
  dom->state = DRIVER_NOT_COMMITED;
  dll_init_list(&(dom->raw_segments));
  dll_init_list(&(dom->segments));
  dll_init_elem(dom, list);

  // Call tyche to create the domain.
   if (create_domain(&(dom->domain_id), aliased) != SUCCESS) {
    ERROR("Monitor rejected the creation of a domain for domain %p", dom);
    goto failure_free;
  }

  // Add the domain to the list.
  dll_add((&domains), dom, list);

  // If the pointer is non null, forward a reference.
  if (ptr != NULL) {
    *ptr = dom;
  }
  LOG("A new domain was added to the driver with id %p", handle);
  return SUCCESS;
failure_free:
  kfree(dom);
failure:
  return FAILURE;
}

EXPORT_SYMBOL(driver_create_domain);

int driver_mmap_segment(driver_domain_t *dom, struct vm_area_struct *vma)
{
  void* allocation = NULL;
  usize size = 0;
  if (vma == NULL || dom->handle == NULL) {
    ERROR("The provided vma is null or handle is null.");
    goto failure;
  }
  // Checks on the vma.
  if (vma->vm_end <= vma->vm_start) {
    ERROR("End is smaller than start");
    goto failure;
  }
  if (vma->vm_start % PAGE_SIZE != 0 || vma->vm_end % PAGE_SIZE != 0) {
    ERROR("End or/and Start is/are not page-aligned.");
    goto failure;
  }
  if (dom == NULL) {
    ERROR("Unable to find the right domain.");
    goto failure;
  }
  if (!dll_is_empty(&(dom->raw_segments)) || !dll_is_empty(&(dom->segments))) {
    ERROR("The domain has already been initialized.");
    goto failure;
  }

  // Allocate a contiguous memory region.
  size = vma->vm_end - vma->vm_start;
  allocation = alloc_pages_exact(size, GFP_KERNEL); 
  if (allocation == NULL) {
    ERROR("Alloca pages exact failed to allocate the pages.");
    goto failure;
  }
  memset(allocation, 0, size);
  // Prevent pages from being collected.
  for (int i = 0; i < (size/PAGE_SIZE); i++) {
    char* mem = ((char*)allocation) + i * PAGE_SIZE;
    SetPageReserved(virt_to_page((unsigned long)mem));
  }

  DEBUG("The phys address %llx, virt: %llx", (usize) virt_to_phys(allocation), (usize) allocation);
  if (vm_iomap_memory(vma, virt_to_phys(allocation), size)) {
    ERROR("Unable to map the memory...");
    goto fail_free_pages;
  }

  if (driver_add_raw_segment(
        dom, (usize) vma->vm_start, 
        (usize) virt_to_phys(allocation), size) != SUCCESS) {
    ERROR("Unable to allocate a segment");
    goto fail_free_pages;
  }
  return SUCCESS;
fail_free_pages:
  free_pages_exact(allocation, size);
failure:
  return FAILURE;
}

int driver_add_raw_segment(
    driver_domain_t *dom,
    usize va,
    usize pa,
    usize size)
{
  segment_t *segment = NULL;
  if (dom == NULL) {
    ERROR("Provided domain is null.");
    goto failure;
  }

  segment = kmalloc(sizeof(segment_t), GFP_KERNEL);
  if (segment == NULL) {
    ERROR("Unable to allocate a segment");
    goto failure;
  }
  memset(segment, 0, sizeof(segment_t));
  segment->va = va;
  segment->pa = pa;
  segment->size = size;
  segment->state = DRIVER_NOT_COMMITED;
  dll_init_elem(segment, list);
  dll_add(&(dom->raw_segments), segment, list);
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_add_raw_segment);

int driver_get_physoffset_domain(driver_domain_t *dom, usize* phys_offset)
{
  if (phys_offset == NULL) {
    ERROR("The provided phys_offset variable is null.");
    goto failure;
  }
  if (dom == NULL) {
    ERROR("The provided domain is NULL.");
    goto failure;
  }
  if (dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain %p has not been initialized, call mmap first!", dom);
    goto failure;
  }
  if (dom->raw_segments.head->list.next != NULL) {
    ERROR("An mmap-based domain should not have more than one raw segment.\n");
    goto failure;
  }
  *phys_offset = dll_head(&(dom->raw_segments))->pa;
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_mprotect_domain(
    driver_domain_t *dom,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe,
    usize alias)
{
  segment_t* head = NULL, *segment = NULL; 

  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  } 

  if (dom->handle != NULL && dom->pid != current->pid) {
    ERROR("Wrong pid for domain");
    ERROR("Expected: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  /// The logic here is as follows:
  /// 1. We can only mprotect the top address of raw segments.
  /// 2. When we do so, we carve out the memory segment and add it to segments.
  /// 3. We adapt the raw segment to point to the next raw address if any.
  if (dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain %p doesn't have mmaped memory.", dom);
    goto failure;
  }

  // Check the properties on the segment.
  head = dll_head(&(dom->raw_segments));

  // Check the mprotect has the correct bounds.
  if (head->va != vstart) {
    ERROR("Out of order specification of segment: wrong start");
    ERROR("Expected: %llx, got: %llx", head->va, vstart);
    goto failure;
  }

  if (head->va + head->size < vstart + size) {
    ERROR("The specified segment is not contained in the raw one.");
    ERROR("Raw: start(%llx) size(%llx)", head->va, head->size);
    ERROR("Prot: start(%llx) size(%llx)", vstart, size);
    goto failure;
  }

  // Add the segment.
  segment = kmalloc(sizeof(segment_t), GFP_KERNEL);
  if (segment == NULL) {
    ERROR("Unable to allocate new segment");
  }

  memset(segment, 0, sizeof(segment_t));
  segment->va = vstart;
  segment->pa = head->pa;
  segment->size = size;
  segment->flags = flags;
  segment->tpe = tpe;
  segment->alias = alias;
  segment->state = DRIVER_NOT_COMMITED;
  dll_init_elem(segment, list);
  dll_add(&(dom->segments), segment, list);

  // Adjust the head.
  // Easy case, we just remove the head.
  if (segment->size == head->size) {
    dll_remove(&(dom->raw_segments), head, list);
    kfree(head);
  } else {
    head->va += size;
    head->pa += size;
    head->size -= size;
  } 
  DEBUG("Mprotect success for domain %lld, start: %llx, end: %llx", 
      domain, vstart, vstart + size);
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_mprotect_domain);

int driver_set_domain_configuration(driver_domain_t *dom, driver_domain_config_t idx, usize value)
{
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }
  if (idx < TYCHE_CONFIG_PERMISSIONS || idx >= TYCHE_NR_CONFIGS) {
    ERROR("Invalid configuration index");
    goto failure;
  }
  dom->configs[idx] = value;
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_set_domain_configuration);

/// Expose the configuration of fields (write).
int driver_set_domain_core_config (driver_domain_t *dom, usize core, usize idx,
                                   usize value) {
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0) {
    ERROR("Trying to set config on unallowed core: %u", (unsigned int) core);
    goto failure;
  }
  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than supported cores.");
    goto failure;
  }
  /*if (dom->state != DRIVER_NOT_COMMITED) {
    ERROR("The domain is already committed or dead: %d", dom->state);
    goto failure;
  }*/
  if (dom->domain_id == UNINIT_DOM_ID) {
    ERROR("The domain is not initialized with tyche");
    goto failure;
  } 
  if (set_domain_core_configuration(dom->domain_id, core, idx, value)
      != SUCCESS) {
    ERROR("Unable to set core configuration");
    goto failure;
  }

  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_set_domain_core_config);


/// Expose the configuration of fields (read).
int driver_get_domain_core_config(driver_domain_t *dom, usize core, usize idx, usize *value) {
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  } 
  if (value == NULL) {
    ERROR("The provided value is null.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0) {
    ERROR("Trying to commit entry point on unallowed core");
    goto failure;
  }
  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than supported cores.");
    goto failure;
  }
  /*if (dom->state != DRIVER_NOT_COMMITED) {
    ERROR("The domain is already committed or dead");
    goto failure;
  }*/
  if (dom->domain_id == UNINIT_DOM_ID) {
    ERROR("The domain is not initialized with tyche");
    goto failure;
  }
  if (get_domain_core_configuration(dom->domain_id, core, idx, value)
      != SUCCESS) {
    ERROR("Unable to get core configuration");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_get_domain_core_config);

int driver_commit_domain_configuration(driver_domain_t *dom, driver_domain_config_t idx)
{
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }
  if (idx < TYCHE_CONFIG_PERMISSIONS || idx >= TYCHE_NR_CONFIGS) {
    ERROR("Invalid configuration index");
    goto failure;
  }
  if (set_domain_configuration(dom->domain_id, idx, dom->configs[idx]) != SUCCESS) {
    ERROR("Capability operation to set configuration");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_commit_domain_configuration);

int driver_alloc_core_context(driver_domain_t *dom, usize core) {
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0) {
    ERROR("Trying to commit entry point on unallowed core");
    goto failure;
  }
  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than supported cores.");
    goto failure;
  }
  if (alloc_core_context(dom->domain_id, core) != SUCCESS) {
    ERROR("Unable to allocate context on core");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_alloc_core_context);

int driver_set_entry_on_core(
    driver_domain_t *dom,
    usize core,
    usize cr3,
    usize rip,
    usize rsp)
{
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0) {
    ERROR("Trying to set entry point on unallowed core");
    goto failure;
  }

  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than the number of supported cores");
    goto failure;
  }

  dom->entries.entries[core].cr3 = cr3;
  dom->entries.entries[core].rip = rip;
  dom->entries.entries[core].rsp = rsp;
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_commit_entry_on_core(driver_domain_t *dom, usize core)
{
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0) {
    ERROR("Trying to commit entry point on unallowed core");
    goto failure;
  }
  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than supported cores.");
    goto failure;
  }

  // Set the domain's registers.
  if (set_domain_core_configuration(
        dom->domain_id, core, REG_GP_RSP, 
        dom->entries.entries[core].rsp) != SUCCESS) {
    ERROR("Unable to set RSP on core %llx", core);
    goto failure;
  } 
  if (set_domain_core_configuration(
        dom->domain_id, core, REG_GP_RIP,
        dom->entries.entries[core].rip) != SUCCESS) {
    ERROR("Unable to set RIP on core %llx", core);
    goto failure;
  }
  if (set_domain_core_configuration(
        dom->domain_id, core, REG_GP_CR3,
        dom->entries.entries[core].cr3) != SUCCESS) {
    ERROR("Unable to set CR3 on core %llx", core);
    goto failure;
  }

  return SUCCESS;
failure:
  return FAILURE;
}

int driver_commit_regions(driver_domain_t *dom)
{
  segment_t* segment = NULL;
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }
  if (dom->handle != NULL && dom->pid != current->pid) {
    ERROR("Wrong pid for dom");
    ERROR("Expected: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  if (dom->domain_id == UNINIT_DOM_ID) {
    ERROR("The domain %p is not registered with the monitor", dom);
    goto failure;
  }
  //TODO(aghosn) we need to figure this out.
  /*if (dom->state != DRIVER_NOT_COMMITED) {
    ERROR("The domain %p is already committed.", dom);
    goto failure;
  }*/
  if (!dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain %p's memory is not correctly initialized.", dom);
    goto failure;
  }
  if (dll_is_empty(&dom->segments)) {
    ERROR("Missing segments for domain %p", dom);
    goto failure;
  }
  // Add the segments.
  dll_foreach(&(dom->segments), segment, list) {
    // Skip segments already commited;
    if (segment->state == DRIVER_COMMITED) {
      continue;
    }
    switch(segment->tpe) {
      case SHARED:
        if (share_region(
              dom->domain_id, 
              segment->pa,
              segment->size,
              segment->flags, segment->alias) != SUCCESS) {
          ERROR("Unable to share segment %llx -- %llx {%x}", segment->va,
              segment->size, segment->flags);
          goto delete_fail;
        }
        break;
      case CONFIDENTIAL:
        if (grant_region(
              dom->domain_id,
              segment->pa,
              segment->size,
              segment->flags, segment->alias) != SUCCESS) {
          ERROR("Unable to share segment %llx -- %llx {%x}", segment->va,
              segment->size, segment->flags);
          goto delete_fail;
        }
        break;
	case SHARED_REPEAT:
		if (share_repeat_region(dom->domain_id,
					segment->pa,
					segment->size,
					segment->flags,
					segment->alias) != SUCCESS) {
			ERROR("Unable to share repeat segment %llx -- %llx {%x}",
					segment->va, segment->size, segment->flags);
			goto delete_fail;
		}
		break;
      default:
        ERROR("Invalid tpe for segment!");
        goto delete_fail;
    }
    segment->state = DRIVER_COMMITED;
    DEBUG("Registered segment with tyche: %llx -- %llx [%x]",
        segment->pa, segment->pa + segment->size, segment->tpe);
  }
  return SUCCESS;
delete_fail:
  if (revoke_domain(dom->domain_id) != SUCCESS) {
    ERROR("Failed to revoke the domain %lld for domain %p.", dom->domain_id, dom);
  }
  dom->domain_id = UNINIT_DOM_ID;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_commit_regions);

int driver_commit_domain(driver_domain_t *dom, int full)
{
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  } 
  if (dom->handle != NULL && dom->pid != current->pid) {
    ERROR("Wrong pid for dom");
    ERROR("Expected: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  if (!dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain %p's memory is not correctly initialized.", dom);
    goto failure;
  }
  if (dll_is_empty(&dom->segments)) {
    ERROR("WARNING: the domain %p has no segment.", dom);
    //goto failure;
  }

  if (dom->domain_id == UNINIT_DOM_ID) {
    ERROR("The domain %p is not registered with the monitor", dom);
    goto failure;
  }

  if (dom->state != DRIVER_NOT_COMMITED) {
    ERROR("The domain %p is already committed.", dom);
    goto failure;
  }

  // We need to commit some of the configuration.
  if (full != 0) {
    usize core_map = dom->configs[TYCHE_CONFIG_CORES];
    if (driver_commit_regions(dom) != SUCCESS) {
      ERROR("Failed to commit regions.");
      goto failure;
    }
    
    // The configurations.
    for (int i = 0; i < TYCHE_NR_CONFIGS; i++) {
      if (driver_commit_domain_configuration(dom, i) != SUCCESS) {
        ERROR("Failed to commit config %d", i);
        goto failure;
      }
    }

    // Set the entries.
    for (int i = 0; i < ENTRIES_PER_DOMAIN; i++) {
      if (((1 << i) & core_map) == 0) {
        continue;
      }
      // Allocate the context for the core.
      if (driver_alloc_core_context(dom, i) != SUCCESS) {
        ERROR("Unable to allocate context for core %d", i);
        goto failure;
      }
      // Set the entry.
      if (driver_commit_entry_on_core(dom, i) != SUCCESS) {
        ERROR("Unable to set entry capability for core %d", i); 
        goto failure;
      }
    } 
  }
  // Commit the domain.
  if (seal_domain(dom->domain_id) != SUCCESS) {
    ERROR("Unable to seal domain %p", dom);
    goto failure;
  }
  
  // Mark the state of the domain as committed.
  dom->state = DRIVER_COMMITED;
  
  DEBUG("Managed to seal domain %lld | dom %p", dom->domain_id, dom->handle);
  // We are all done!
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_commit_domain);

int driver_switch_domain(driver_domain_t * dom, void* args)
{
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  DEBUG("About to try to switch to domain %lld| dom %lld",
      dom->domain_id, dom->handle);
  if (switch_domain(dom->domain_id, args) != SUCCESS) {
    ERROR("Unable to switch to domain %p", dom->handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_switch_domain);

int driver_delete_domain(driver_domain_t *dom)
{
  segment_t* segment = NULL;
  usize phys_start = 0;
  usize size = 0;
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  if (dom->domain_id == UNINIT_DOM_ID) {
    goto delete_dom_struct;
  }
  if (revoke_domain(dom->domain_id) != SUCCESS) {
    ERROR("Unable to delete the domain %lld for domain %p",
        dom->domain_id, dom);
    goto failure;
  }

delete_dom_struct:
  // Delete all segments;
  while(!dll_is_empty(&(dom->segments))) {
    segment = dll_head(&(dom->segments));
    if (phys_start == 0) {
      phys_start = segment->pa;
    }
    size += segment->size;
    dll_remove(&(dom->segments), segment, list);
    kfree(segment);
    segment = NULL;
  }

  // Delete the domain memory region.
  // If the memory was allocated with mmap, we need to free the pages.
  if (dom->handle != NULL) {
    free_pages_exact(phys_to_virt((phys_addr_t)(phys_start)), size);
  }
  dll_remove(&domains, dom, list);
  kfree(dom);
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_delete_domain);
