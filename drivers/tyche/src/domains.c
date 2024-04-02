#include "arch_cache.h"
#include "dll.h"
#include "linux/rwsem.h"
#include "tyche_api.h"
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <asm/io.h>
#include <linux/fs.h>

#if defined(CONFIG_X86) || defined(__x86_64__)
#include <asm/vmx.h>
#elif defined(CONFIG_RISCV) || defined(__riscv)
#include "tyche_register_map.h"
#endif

#include "common.h"
#include "common_log.h"
#include "domains.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"
#include "arch_cache.h"

// ————————————————————————— Helpers for lock state ————————————————————————— //

// For the moment we disable the lock-checks for domains managed by KVM.
// This is done by first checking the handle is not null.

#define CHECK_RLOCK(dom, failure_label) \
    if (dom->handle != NULL && down_write_trylock(&(dom->rwlock)) == 1) { \
      ERROR("The domain should be R-locked."); \
      up_write(&(dom->rwlock)); \
      goto failure_label; \
    }

#define CHECK_WLOCK(dom, failure_label) \
    if (dom->handle != NULL && down_read_trylock(&(dom->rwlock)) == 1) { \
      ERROR("The domain should be W-locked."); \
      up_read(&(dom->rwlock)); \
      goto failure_label; \
    }

// ———————————————————————————————— Globals ————————————————————————————————— //

typedef struct global_state_t {
  // R/W-lock to access domains.
  struct rw_semaphore rwlock;
  // The list of domains managed by the driver.
  // Accesses should acquire the appropriate R/W-lock.
  dll_list(driver_domain_t, domains);
  // R/W-lock to access pipes.
  struct rw_semaphore rwlock_pipes;
  // The next pipe id.
  usize next_pipe_id;
  // The list of pipes.
  dll_list(driver_pipe_t, pipes);
} global_state_t;

static global_state_t state;


static int state_add_domain(driver_domain_t* dom) {
  if (dom == NULL) {
    ERROR("The supplied domain is null.");
    goto failure;
  }

  if (dom->list.next != NULL || dom->list.prev != NULL) {
    ERROR("The domain is already in a list?");
    goto failure;
  }

  // W-lock the list.
  down_write(&(state.rwlock));
  dll_add(&(state.domains), dom, list);
  up_write(&(state.rwlock)); 
  return SUCCESS;
failure:
  return FAILURE;
}

static int state_remove_domain(driver_domain_t * dom) {
  if (dom == NULL) {
    ERROR("The supplied domain is null.");
    goto failure;
  }
  if (dom->handle == NULL) {
    ERROR("Trying to remove a domain with null handle.");
    goto failure;
  }
  CHECK_WLOCK(dom, failure);
  down_write(&(state.rwlock)); 
  dll_remove(&(state.domains), dom, list);
  up_write(&(state.rwlock));
  return SUCCESS;
failure:
  return FAILURE;
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

driver_domain_t* find_domain(domain_handle_t handle, bool write)
{
  driver_domain_t* dom = NULL;
  down_read(&(state.rwlock));
  dll_foreach((&(state.domains)), dom, list) {
    if (dom->handle == handle) {
      break;
    }
  }
  if (dom == NULL) {
    goto failure;
  }
  if (dom->pid != current->tgid) {
    ERROR("Attempt to access dom %p from wrong pid", handle);
    ERROR("Expected pid: %d, got: %d", dom->pid, current->tgid);
    goto failure;
  }
  // Acquire the lock on the domain.
  if (write) {
    down_write(&(dom->rwlock));
  } else {
    down_read(&(dom->rwlock));
  }
  up_read(&(state.rwlock));
  return dom;
failure:
  up_read(&(state.rwlock));
  return NULL;
}


// ——————————————————————————————— Functions ———————————————————————————————— //

void driver_init_domains(void)
{
  init_rwsem(&(state.rwlock));
  dll_init_list((&(state.domains)));
  state.next_pipe_id = 0;
  init_rwsem(&(state.rwlock));
  dll_init_list(&(state.pipes));
  driver_init_capabilities();
}


int driver_create_domain(domain_handle_t handle, driver_domain_t** ptr, int aliased)
{
  driver_domain_t* dom = NULL;
  // This function can be called from the kvm backend as well.
  // In such cases, the domain handle will be null.
  if (handle == NULL && ptr == NULL) {
    ERROR("Domain without a handle should provide a non-null ptr.");
    goto failure;
  }
  dom = (handle != NULL)? find_domain(handle, false) : NULL;
  if (dom != NULL) {
    ERROR("The domain with handle %p already exists.", handle);
    // Unlock the domain.
    up_read(&(dom->rwlock));
    goto failure;
  }
  dom = kmalloc(sizeof(driver_domain_t), GFP_KERNEL);
  if (dom == NULL) {
    ERROR("Failed to allocate a new driver_domain_t structure.");
    goto failure;
  }
  memset(dom, 0, sizeof(driver_domain_t));
  // Set up the structure.
  dom->pid = current->tgid;
  dom->handle = handle;
  dom->domain_id = UNINIT_DOM_ID;
  dom->state = DRIVER_NOT_COMMITED;
  init_rwsem(&(dom->rwlock));
  dll_init_list(&(dom->raw_segments));
  dll_init_list(&(dom->segments));
  dll_init_elem(dom, list);

  // Call tyche to create the domain.
   if (create_domain(&(dom->domain_id), aliased) != SUCCESS) {
    ERROR("Monitor rejected the creation of a domain for domain %p", dom);
    goto failure_free;
  }

  // Add the domain to the list if it has a handle.
  // Domains without handles come from KVM.
  if (handle != NULL && ptr == NULL) {
    state_add_domain(dom);
  }

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
  int order;
  if (vma == NULL || dom->handle == NULL) {
    ERROR("The provided vma is null or handle is null.");
    goto failure;
  }
  // Expect the domain to be w-locked.
  CHECK_WLOCK(dom, failure);

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
  if (!dll_is_empty(&(dom->segments))) {
    ERROR("The domain has already been initialized.");
    goto failure;
  }

  // Allocate a contiguous memory region.
  // If the order of the size requested is too big, fail.
  // This should be handled inside the loader, not the driver.
  size = vma->vm_end - vma->vm_start;
  order = get_order(size);
  if (order >= MAX_ORDER) {
    ERROR("The requested size of: %llx has order %d while max order is %d",
        size, order, MAX_ORDER);
    goto failure;
  }
  allocation = alloc_pages_exact(size, GFP_KERNEL); 
  if (allocation == NULL) {
    ERROR("Alloca pages exact failed to allocate the pages for size %llx.", size);
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
  // Expects to be w-locked.
  CHECK_WLOCK(dom, failure);

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

int driver_get_physoffset_domain(driver_domain_t *dom, usize slot_id, usize* phys_offset)
{
  segment_t *seg = NULL;
  usize slot_counter = 0;
  if (phys_offset == NULL) {
    ERROR("The provided phys_offset variable is null.");
    goto failure;
  }
  if (dom == NULL) {
    ERROR("The provided domain is NULL.");
    goto failure;
  }
  // We expect to have a r-lock on the domain.
  CHECK_RLOCK(dom, failure);

  if (dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain %p has not been initialized, call mmap first!", dom);
    goto failure;
  }
  dll_foreach(&(dom->raw_segments), seg, list) {
    if (slot_counter == slot_id) {
      *phys_offset = seg->pa;
      return SUCCESS;
    }
    slot_counter++;
  }
  ERROR("Failure to find the right memslot %lld.\n", slot_id);
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

  /// Expects the domain to be write-locked.
  CHECK_WLOCK(dom, failure);

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
  // Expects the domain to be W-locked.
  CHECK_WLOCK(dom, failure);

  if (idx < TYCHE_CONFIG_PERMISSIONS || idx >= TYCHE_NR_CONFIGS) {
    ERROR("Invalid configuration index");
    goto failure;
  }
  dom->configs[idx] = value;
  // Register this directly with tyche.
  if (set_domain_configuration(dom->domain_id, idx, dom->configs[idx]) != SUCCESS) {
    ERROR("Capability operation to set configuration");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_set_domain_configuration);

/// Expose the domain's own configuration for allowed selected fields.
int driver_set_self_core_config(usize field, usize value) {
  return tyche_set_self_core_config(field, value);
}
EXPORT_SYMBOL(driver_set_self_core_config);

/// Expose the configuration of fields (write).
int driver_set_domain_core_config (driver_domain_t *dom, usize core, usize idx,
                                   usize value) {
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }

  // Expects the domain to be R-locked.
  CHECK_RLOCK(dom, failure);

  /*if (dom->state != DRIVER_NOT_COMMITED) {
    ERROR("The domain is already committed or dead: %d", dom->state);
    goto failure;
  }*/
  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than supported cores.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0 ||
      dom->contexts[core] == NULL) {
    ERROR("Trying to set config on unallowed/unallocated core: %u", (unsigned int) core);
    goto failure;
  }
  
  // Lock the core context.
  down_write(&(dom->contexts[core]->rwlock));

  if (cache_write_any(&(dom->contexts[core]->cache), idx, value) != SUCCESS) {
    ERROR("Unable to write the value in the cache %llx.\n", idx);  
    up_write(&(dom->contexts[core]->rwlock));
    goto failure;
  }
  up_write(&(dom->contexts[core]->rwlock));
  //TODO(aghosn): we need to flush later.
  /*if (dom->domain_id == UNINIT_DOM_ID) {
    ERROR("The domain is not initialized with tyche");
    goto failure;
  } 
  if (set_domain_core_configuration(dom->domain_id, core, idx, value)
      != SUCCESS) {
    ERROR("Unable to set core configuration");
    goto failure;
  }*/

  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_set_domain_core_config);


/// Expose the configuration of fields (read).
int driver_get_domain_core_config(driver_domain_t *dom, usize core, usize idx, usize *value) {
  u64 v = 0;
  int res = FAILURE;
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  } 

  // Expects the domain to be R-locked.
  CHECK_RLOCK(dom, failure);

  if (value == NULL) {
    ERROR("The provided value is null.");
    goto failure;
  }
  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("The supplied core is greater than supported cores.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0 ||
      dom->contexts[core] == NULL) {
    ERROR("Trying to commit entry point on unallowed/unallocated core");
    goto failure;
  }
  /*if (dom->state != DRIVER_NOT_COMMITED) {
    ERROR("The domain is already committed or dead");
    goto failure;
  }*/

  // First try a read-lock.
  down_read(&(dom->contexts[core]->rwlock));
  // The value was in the cache.
  if (cache_read_any(&(dom->contexts[core]->cache), idx, &v) == 0) {
      *value = v;
      up_read(&(dom->contexts[core]->rwlock));
      return SUCCESS;
  }
  // Unlock, we will have to get a write lock on the context.
  up_read(&(dom->contexts[core]->rwlock));
  // The value is not in the cache.
  if (dom->domain_id == UNINIT_DOM_ID) {
    ERROR("The domain is not initialized with tyche");
    goto failure;
  }

  // acquire the write lock on the context.
  down_write(&(dom->contexts[core]->rwlock));
  if (get_domain_core_configuration(dom->domain_id, core, idx, value)
      != SUCCESS) {
    ERROR("Unable to get core configuration");
    up_write(&(dom->contexts[core]->rwlock));
    goto failure;
  }
  // Update the cache.
  res = cache_set_any(&(dom->contexts[core]->cache), idx, *value);
  if (res != 0) {
    ERROR("Unable to update the cache value %llx, %d\n", idx, res);
    up_write(&(dom->contexts[core]->rwlock));
    return FAILURE;
  }
  up_write(&(dom->contexts[core]->rwlock));
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_get_domain_core_config);

int driver_alloc_core_context(driver_domain_t *dom, usize core) {
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  // The domain must be W-locked.
  CHECK_WLOCK(dom, failure);

  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0 ||
      dom->contexts[core] != NULL) {
    ERROR("Trying to commit entry point on unallowed/allocated core");
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
  // Allocate the context for this core.
  dom->contexts[core] = kmalloc(sizeof(arch_cache_t), GFP_KERNEL); 
  if (dom->contexts[core] == NULL) {
    ERROR("Unable to allocate a context.");
    goto failure;
  }
  // Set everything to 0.
  memset(dom->contexts[core], 0, sizeof(arch_cache_t));
  init_rwsem(&(dom->contexts[core]->rwlock));
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_alloc_core_context);

int driver_commit_regions(driver_domain_t *dom)
{
  segment_t* segment = NULL;
  if (dom == NULL) {
    ERROR("The domain is null");
    goto failure;
  }
  // Expect the domain to be W-locked.
  CHECK_WLOCK(dom, failure);

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
          goto failure;
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
          goto failure;
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
      goto failure;
    }
    break;
      default:
        ERROR("Invalid tpe for segment!");
        goto failure;
    }
    segment->state = DRIVER_COMMITED;
    DEBUG("Registered segment with tyche: %llx -- %llx [%x]",
        segment->pa, segment->pa + segment->size, segment->tpe);
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_commit_regions);

// This is called from us so we should be okay with the values passed.
// Every corner case should have been checked before hand.
static int flush_caches(driver_domain_t *dom, usize core) {
  int i = 0;
  u64 values[114]; 
  u64 fields[114];
  int to_write = 0;
  memset(values, 0xFF, sizeof(values));
  memset(fields, 0xFF, sizeof(fields));
  to_write = cache_collect_dirties(&(dom->contexts[core]->cache), values, fields, 114);
  if (to_write < 0) {
    ERROR("Our buffer is too small, need: %d", cache_dirty_count(&(dom->contexts[core]->cache)));
    return -1;
  }
  // Write the registers.
  while (i < to_write) {
    int end = ((i + 6) <= to_write)? i+6 : to_write; 
    if (write_fields(dom->domain_id, core, fields+i, values+i, end - i) != SUCCESS) {
      ERROR("Trouble writting the values to domain.");
      for (int j = 0; j < end -i; j++) {
        ERROR("field: %llx, value: %llx", fields[i+j], values[i+j]);
      }
      return -1;
    }
    i = end;
  }
  return 0;
}

int driver_commit_domain(driver_domain_t *dom, int full)
{
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  } 
  // The domain must be W-locked.
  CHECK_WLOCK(dom, failure);

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
    //ERROR("Full is not 0");
    if (driver_commit_regions(dom) != SUCCESS) {
      ERROR("Failed to commit regions.");
      goto failure;
    }
    
    // The configurations.
    /*for (int i = 0; i < TYCHE_NR_CONFIGS; i++) {
      //TODO: fix that we will change the run type.
      BUG_ON(1);
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
    }*/
  }
  //ERROR("About to seal the domain.");
  //TODO(aghosn) try to flush the cache.
  for (int i = 0; i < ENTRIES_PER_DOMAIN; i++) {
    if (dom->contexts[i] != NULL) {
      down_write(&(dom->contexts[i]->rwlock));
      if (flush_caches(dom, i) != SUCCESS) {
        ERROR("Unable to flush the cache.");
        up_write(&(dom->contexts[i]->rwlock));
        goto failure;
      }
      cache_clear(&(dom->contexts[i]->cache), 0);
      up_write(&(dom->contexts[i]->rwlock));
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


#if defined(CONFIG_X86) || defined(__x86_64__)
/// The format of the exit frame.
const usize EXIT_FRAME_FIELDS[TYCHE_EXIT_FRAME_SIZE] = {
  GUEST_RIP,
  GUEST_RSP,
  GUEST_RFLAGS,
  VM_INSTRUCTION_ERROR,
  VM_EXIT_REASON,
  VM_EXIT_INTR_INFO,
  VM_EXIT_INTR_ERROR_CODE,
  VM_EXIT_INSTRUCTION_LEN,
  VM_INSTRUCTION_ERROR,
};
#elif defined(CONFIG_RISCV) || defined(__riscv)
/// The format of the exit frame.
const usize EXIT_FRAME_FIELDS[TYCHE_EXIT_FRAME_SIZE] = {
  GUEST_RIP,
  GUEST_RSP,
  GUEST_CR3,
  EXCEPTION_BITMAP,
};
#endif
// Flush the exit frame.
// This is called internally and corner cases should have been checked.
static int update_set_exit(driver_domain_t *dom, usize core, usize exit[TYCHE_EXIT_FRAME_SIZE]) {
  int i = 0;
  arch_cache_t* cache = &(dom->contexts[core]->cache);
  for (i = 0; i < TYCHE_EXIT_FRAME_SIZE; i++) {
    if (cache_set_any(cache, EXIT_FRAME_FIELDS[i], exit[i]) != SUCCESS) {
      ERROR("Unable to set a cache values?");
      goto failure;
    }
  }
  return SUCCESS;
failure:
  return FAILURE;
}

const usize GP_REGS_FIELDS[TYCHE_GP_REGS_SIZE] = {
  REG_GP_RAX,
  REG_GP_RBX,
  REG_GP_RCX,
  REG_GP_RDX,
  REG_GP_RBP,
  REG_GP_RSI,
  REG_GP_RDI,
  REG_GP_R8 ,
  REG_GP_R9 ,
  REG_GP_R10,
  REG_GP_R11,
  REG_GP_R12,
  REG_GP_R13,
  REG_GP_R14,
  REG_GP_R15, 
};

static int update_set_gp(driver_domain_t *dom, usize core, usize regs[TYCHE_GP_REGS_SIZE])  {
  int i = 0;
  arch_cache_t *cache = &(dom->contexts[core]->cache);
  for (i = 0; i < TYCHE_GP_REGS_SIZE; i++) {
    if (cache_set_any(cache, GP_REGS_FIELDS[i], regs[i]) != SUCCESS) {
      ERROR("Unable to set a gp cache value?");
      goto failure;
    }
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_switch_domain(driver_domain_t * dom, usize core) {
  usize exit_frame[TYCHE_EXIT_FRAME_SIZE] = {0};
  usize gp_frame[TYCHE_GP_REGS_SIZE] = {0};
  int local_cpuid = 0;
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  // Expects the domain to be R-locked.
  CHECK_RLOCK(dom, failure);

  if (core >= ENTRIES_PER_DOMAIN) {
    ERROR("Invalid core.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << core)) == 0 ||
      dom->contexts[core] == NULL) {
    ERROR("Invalid core.");
    goto failure;
  }

  // Lock the core.
  down_write(&(dom->contexts[core]->rwlock));

  // This disables preemption to guarantee we remain on the same core after the
  // check.
  local_cpuid = get_cpu();
  // Check we are on the right core.
  if (core != local_cpuid) {
    ERROR("Attempt to switch on core %lld from cpu %d", core, local_cpuid);
    goto failure_unlock;
  }

  // LOCK THE CORE CONTEXT.
  // Hold the lock until we return from the switch.

  // Let's flush the caches.
  if (flush_caches(dom, core) != SUCCESS) {
    ERROR("Unable to flush caches.");
    goto failure_unlock;
  }

  // We can clear the cache now.
  cache_clear(&(dom->contexts[core]->cache), 1);

  DEBUG("About to try to switch to domain %lld", dom->domain_id);
  if (switch_domain(dom->domain_id, exit_frame) != SUCCESS) {
    ERROR("Unable to switch to domain %p", dom->handle);
    goto failure_unlock;
  }

  // Update the exit frame.
  if (update_set_exit(dom, core, exit_frame) != SUCCESS) {
    ERROR("Unable to update the exit frame.");
    goto failure_unlock;
  }
  // Get the gp registers.
  // TODO(aghosn) See if it's really necessary or not.
  if (read_gp_domain(dom->domain_id, core, gp_frame) != SUCCESS) {
    ERROR("Unable to read the domain's general purpose registers.");
    goto failure_unlock;
  }
  if (update_set_gp(dom, core, gp_frame) != SUCCESS) {
    ERROR("Unable to set the domain's general purpose registers.");
    goto failure_unlock;
  }

  // Reenable the preemption.
  put_cpu();
  // UNLOCK THE CORE CONTEXT.
  up_write(&(dom->contexts[core]->rwlock));
  return SUCCESS;
failure_unlock:
  put_cpu();
  up_write(&(dom->contexts[core]->rwlock));
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_switch_domain);

int driver_delete_domain(driver_domain_t *dom)
{
  segment_t* segment = NULL;
  usize size = 0;
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }

  /// We cannot delete if we do not have exclusive access to the domain.
  CHECK_WLOCK(dom, failure);
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
    size += segment->size;
    dll_remove(&(dom->segments), segment, list);
    //TODO: this creates a bug if user code calls munmap.
    /*if (dom->handle != NULL) {
      free_pages_exact(phys_to_virt((phys_addr_t)(segment->pa)), size);
    }*/
    kfree(segment);
    segment = NULL;
  }

  // Delete the contexts.
  for (int i = 0; i < ENTRIES_PER_DOMAIN; i++) {
    if (dom->contexts[i] != NULL) {
      kfree(dom->contexts[i]);
    }
  } 
  if (dom->handle != NULL && state_remove_domain(dom) != SUCCESS) {
    ERROR("Unable to remove the domain from the state list.");
    goto failure;
  }
  kfree(dom);
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_delete_domain);


int driver_delete_domain_regions(driver_domain_t *dom)
{
  segment_t* segment = NULL;
  usize size = 0;
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }

  // The domain should be W-locked.
  CHECK_WLOCK(dom, failure);

  if (dom->domain_id == UNINIT_DOM_ID) {
    goto delete_dom_struct;
  }
  if (revoke_domain_regions(dom->domain_id) != SUCCESS) {
    ERROR("Unable to delete the domain %lld for domain %p", dom->domain_id, dom);
    goto failure;
  }
delete_dom_struct:
  // Delete all segments;
  while(!dll_is_empty(&(dom->segments))) {
    segment = dll_head(&(dom->segments));
    size += segment->size;
    dll_remove(&(dom->segments), segment, list);
    kfree(segment);
    segment = NULL;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_delete_domain_regions);

int driver_create_pipe(usize *pipe_id, usize phys_addr, usize size,
           memory_access_right_t flags, usize width) {
  capability_t* orig = NULL;
  capability_t* orig_revoke = NULL;
  driver_pipe_t* pipe = NULL;
  usize i = 0;
  if (pipe_id == NULL || width == 0) {
    ERROR("Supplied pipe id is null");
    goto failure;
  }
  pipe = kmalloc(sizeof(driver_pipe_t), GFP_KERNEL);
  if (pipe == NULL) {
    ERROR("Unable to allocate pipe");
    goto failure;
  }
  pipe->id = 0;
  pipe->phys_start = phys_addr;
  pipe->size = size;
  dll_init_list(&(pipe->actives));
  dll_init_list(&(pipe->revokes));
  dll_init_elem(pipe, list);
  if (cut_region(phys_addr, size, flags, &orig, &orig_revoke) != SUCCESS) {
    ERROR("Unable to carve out the original pipe region.");
    goto failure_free;
  }
  dll_add(&(pipe->actives), orig, list);
  dll_add(&(pipe->revokes), orig_revoke, list);

  for (i = 0; i < width -1; i++) {
    capability_t* dup = NULL;
    capability_t* dup_revoke = NULL;
    if (dup_region(orig, &dup, &dup_revoke) != SUCCESS) {
      ERROR("Could not duplicate pipe");
      // TODO we should clean the state.
      goto failure;
    }
    dll_add(&(pipe->actives), dup, list);
    dll_add(&(pipe->revokes), dup_revoke, list);
  }

  // Now add the pipe to the driver.
  down_write(&(state.rwlock_pipes));
  pipe->id = state.next_pipe_id++;
  dll_add(&(state.pipes), pipe, list);
  up_write(&(state.rwlock_pipes));
  *pipe_id = pipe->id;
  return SUCCESS;
failure_free:
  kfree(pipe);
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_create_pipe);

int driver_acquire_pipe(driver_domain_t *domain, usize pipe_id) {
  driver_pipe_t *pipe = NULL;
  capability_t* to_send = NULL;
  capability_t* to_revoke = NULL;
  if (domain == NULL) {
    goto failure;
  }
  CHECK_WLOCK(domain, failure);
  down_write(&(state.rwlock_pipes));
  dll_foreach(&(state.pipes), pipe, list) {
    if (pipe->id == pipe_id) {
      // Found it!
      break;
    }
  }
  if (pipe == NULL) {
    ERROR("Could not find the pipe to acquire.");
    goto fail_unlock;
  }
  if (dll_is_empty(&(pipe->actives)) || dll_is_empty(&(pipe->revokes))) {
    ERROR("No width left on that pipe");
    goto fail_unlock;
  }
  // Remove the capas from the pipe.
  to_send = pipe->actives.head;
  to_revoke = pipe->revokes.head;
  dll_remove(&(pipe->actives), to_send, list);
  dll_remove(&(pipe->revokes), to_revoke, list);

  // We can free the pipe.
  if (dll_is_empty(&(pipe->actives)) && dll_is_empty(&(pipe->revokes))) {
    dll_remove(&(state.pipes), pipe, list);
    kfree(pipe);
    pipe = NULL;
  }

  if (send_region(domain->domain_id, to_send, to_revoke) != SUCCESS) {
    ERROR("failed to send the pipes");
    goto fail_unlock;
  }
  up_write(&(state.rwlock_pipes));
  // All went well we're done!
  return SUCCESS;
fail_unlock:
  up_write(&(state.rwlock_pipes));
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_acquire_pipe);

int driver_find_pipe_from_hpa(usize *pipe_id, usize addr, usize size) {
  driver_pipe_t *pipe = NULL;
  if (pipe_id == NULL) {
    goto failure;
  }
  down_write(&(state.rwlock_pipes));
  dll_foreach(&(state.pipes), pipe, list) {
    if (pipe->phys_start == addr && pipe->size == size) {
      // Found it.
      break;
    }
  }
  if (pipe == NULL) {
    ERROR("Unable to find the pipe from address and size");
    goto fail_unlock;
  }
  *pipe_id = pipe->id;
  pipe = NULL;
  up_write(&(state.rwlock_pipes));
  return SUCCESS;
fail_unlock:
  up_write(&(state.rwlock_pipes));
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_find_pipe_from_hpa);

int driver_serialize_attestation(char *addr, usize size, usize *written) {
    usize phys = virt_to_phys(addr);
    return tyche_serialize_attestation(phys, size, written);
}
EXPORT_SYMBOL(driver_serialize_attestation);
