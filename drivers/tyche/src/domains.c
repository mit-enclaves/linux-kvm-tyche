#include "arch_cache.h"
#include "asm-generic/memory_model.h"
#include "asm/page_types.h"
#include "asm/uaccess.h"
#include "dll.h"
#include "linux/export.h"
#include "linux/gfp_types.h"
#include "linux/nmi.h"
#include "linux/rwsem.h"
#include "linux/swiotlb.h"
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

static void dump_list(segment_list_t* l) {
  segment_t* iter = NULL;
  dll_foreach(l, iter, list) {
    printk(KERN_ERR "[0x%llx, 0x%llx] -> [0x%llx, 0x%llx]", iter->va, iter->va + iter->size,
        iter->pa, iter->pa + iter->size);
  }
}
// ——————————————————————————————— Parameters ——————————————————————————————— //
static bool tyche_coco = false;

module_param(tyche_coco, bool, 000);
MODULE_PARM_DESC(tyche_coco, "Transition into a confidential VM.");

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

#ifdef CONFIG_CONFIDENTIAL_VM
extern int tyche_confidential_mmio;
#endif

int driver_revoke_manager_access(void)
{
  capability_t* capa = local_domain.capabilities.head;
  int revoked = 0;
  while(capa != NULL) {
    capability_t* to_revoke = NULL;
    if (capa->capa_type != RegionRevoke) {
      capa = capa->list.next;
      continue;
    }
    to_revoke = capa;
    capa = capa->list.next;
    if (tyche_revoke(to_revoke->local_id) != SUCCESS) {
      ERROR("Unable to revoke ");
      goto failure;
    }
    dll_remove(&(local_domain.capabilities), to_revoke, list);
    local_domain.dealloc(to_revoke);
    revoked++;
  }
#ifdef CONFIG_CONFIDENTIAL_VM
  if (revoked > 0 || tyche_coco) {
    tyche_confidential_mmio = 1;
    swiotlb_print_info();
    pr_err("Tyche driver transitionned into confidential mmio.\n");
  }
#endif
  return revoked;
failure:
  return 0;
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
  dll_init_list(&(dom->to_free_on_delete));
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
  //Disabled for benchmarks
  //LOG("A new domain was added to the driver with id %p", handle);
  return SUCCESS;
failure_free:
  kfree(dom);
failure:
  return FAILURE;
}

EXPORT_SYMBOL(driver_create_domain);

int driver_get_mgmt_capa(driver_domain_t* dom, capa_index_t* capa)
{
  CHECK_RLOCK(dom, failure);
  if (capa == NULL) {
    ERROR("Capa pointer is null");
    goto failure;
  }
  if (get_domain_capa(dom->domain_id, capa) != SUCCESS) {
    ERROR("Unable to read the management capa.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_tyche_check_coalesce(driver_domain_t* dom, bool raw)
{
  segment_list_t* l = NULL;
  segment_t* curr = NULL;
  if (dom == NULL) {
    ERROR("Nul domain");
    goto failure;
  }
  l = (raw)? &(dom->raw_segments) : &(dom->segments);
  curr = l->head;
  while (curr != NULL && curr->list.next != NULL) {
    segment_t* n = curr->list.next;
    // Is it ordered?
    if (curr->va >= n->va) {
      ERROR("The list (%d) is not ordered: curr_va: %llx, n_va: %llx",
          raw, curr->va, n->va);
      dump_list(l);
      goto failure;
    }
    // Does it overlap? Allow overlaps with KVM
    if (dom->handle != NULL && dll_overlap(curr->va, (curr->va + curr->size),
          n->va, (n->va + n->size))) {
      ERROR("Overlap detected %d.", raw);
      ERROR("[%llx, %llx] overlaps [%llx, %llx]", curr->va, curr->va + curr->size,
          n->va, n->va + n->size);
      dump_list(l);
      goto failure;
    }
    // Can we merge? vas and pas need to be contiguous
    if ((curr->va + curr->size) == n->va &&
        (curr->pa + curr->size) == n->pa &&
        (raw || (curr->tpe == n->tpe && curr->flags == n->flags))) {
      curr->size += n->size;
      dll_remove(l, n, list);
      // Free the merged region.
      kfree(n);
      n = NULL;
      continue;
    }
    // Done, proceed to the next.
    curr = curr->list.next;
  }

  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_tyche_check_coalesce);

int driver_tyche_mmap(segment_list_t *raw, segment_list_t* free_list, struct vm_area_struct* vma)
{
  void* allocation = NULL;
  usize size = 0;
  unsigned long vaddr = 0, max_size = 0x400000;
  int order;
  if (vma == NULL || raw == NULL) {
    ERROR("Arguments are null.");
    goto failure;
  }
  size = vma->vm_end - vma->vm_start;
  vaddr = vma->vm_start;
  while (vaddr < vma->vm_end) {
    usize left_to_map = vma->vm_end - vaddr, to_map = 0;
    unsigned long pfn = 0;
    segment_t* to_free = NULL;
    order = get_order(left_to_map);
    to_map = (order < MAX_ORDER)? left_to_map : max_size;
    allocation = alloc_pages_exact(to_map, GFP_KERNEL);
    if (allocation == NULL) {
      ERROR("alloc_pages_exact failed to allocated %llu bytes", to_map);
      goto failure;
    }
    memset(allocation, 0, to_map);
    for (int i = 0; i < (to_map/PAGE_SIZE); i++) {
      char* mem = ((char*)allocation) + i * PAGE_SIZE;
      SetPageReserved(virt_to_page((unsigned long)mem));
    }
    pfn = virt_to_phys(allocation) >> PAGE_SHIFT;
    if (remap_pfn_range(vma, vaddr, pfn, to_map, vma->vm_page_prot) < 0) {
      ERROR("remap_pfn_range failed with vaddr %lx, pfn %lx, size %llx",
          vaddr, pfn, to_map);
      goto failure;
    }
    // Add the segment to the domain.
    if (driver_add_raw_segment(
        raw, (usize) vaddr,
        (usize) virt_to_phys(allocation), to_map) != SUCCESS) {
      ERROR("Unable to allocate a segment");
      goto failure;
    }
    to_free = (segment_t*) kmalloc(sizeof(segment_t), GFP_KERNEL);
    if (to_free == NULL) {
      ERROR("Unable to allocate segment to free.");
      goto failure;
    }
    memset(to_free, 0, sizeof(segment_t));
    dll_init_elem(to_free, list);
    to_free->va = (usize) allocation;
    to_free->size = to_map;
    to_free->pa = virt_to_phys(allocation);
    dll_add(free_list, to_free, list);

    /* Update the vaddr */
    vaddr += to_map;
    allocation = NULL;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_tyche_mmap);

int driver_mmap_segment(driver_domain_t *dom, struct vm_area_struct *vma)
{
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

  //TODO(aghosn): we accept adding segments.
  /*
  if (!dll_is_empty(&(dom->segments))) {
    ERROR("The domain has already been initialized.");
    goto failure;
  }*/

  if (driver_tyche_mmap(&(dom->raw_segments), &(dom->to_free_on_delete), vma) != SUCCESS) {
    ERROR("Unable to mmap vma 0x%lx - 0x%lx", vma->vm_start, vma->vm_end);
    goto failure;
  }

  /* Attempt a cleanup of the domain.*/
  if (driver_tyche_check_coalesce(dom, true) != SUCCESS) {
    ERROR("Something went wrong with check and coalesce.\n");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_internal_register_mmap(segment_list_t* raw, usize virtaddr, usize vsize)
{
  struct page **pages;
  unsigned long start_addr, end_addr;
  unsigned long page_count, i, idx_start;
  unsigned long pfn_prev, pfn_curr, pfn_start;
  int ret;
  if (raw == NULL) {
    ERROR("The raw segment list is null");
    goto failure;
  }
  // Nothing to do if size is null.
  if (vsize == 0) {
    goto success;
  }
  // Check this is a valid address range.
  if (!access_ok((void*) virtaddr, vsize)) {
    ERROR("Invalid range of addresses");
    goto failure;
  }

  // Go through the entire region and split physically contiguous ranges.
  // Register each contiguous range as a raw segment in the domain.
  // First we compute the number of pages (page_count).
  // Then, we use linux to give us every page in the range.
  // This process pins the pages in the address space.
  // After that, we can go through the list of pages to find contiguous ranges.
  start_addr = virtaddr & PAGE_MASK;
  end_addr = (virtaddr + vsize + PAGE_SIZE -1) & PAGE_MASK;
  page_count = (end_addr - start_addr) >> PAGE_SHIFT;
  pages = kmalloc_array(page_count, sizeof(struct page *), GFP_KERNEL);
  if (!pages) {
    ERROR("Unable to allocate the pages.");
    goto failure;
  }
  // This will pin the pages in the address space.
  ret = get_user_pages_fast(virtaddr, page_count, 1, pages);
  if (ret != page_count) {
    ERROR("Unable to get user pages");
    goto failure_free;
  }

  // Look for contiguous ranges.
  pfn_prev = page_to_pfn(pages[0]);
  pfn_start = pfn_prev;
  idx_start = 0;
  start_addr = virtaddr & PAGE_MASK;
  for (i = 0; i < page_count; i++) {
    pfn_curr = page_to_pfn(pages[i]);
    // we have a split or we are the last entry.
    if ((i != 0 && (pfn_curr != pfn_prev + 1)) || i == (page_count-1)) {
      // Compute the end of the range (no -1 because we add the size of the page).
      // We also need to account for the page at index i being included or not.
      unsigned long incr = (i == (page_count -1))? 1 : 0;
      unsigned long size = (i - idx_start + incr) * PAGE_SIZE;
      if (driver_add_raw_segment(raw, (usize) start_addr,
           (usize)(pfn_start << PAGE_SHIFT), size) != SUCCESS) {
        ERROR("Unable to add raw segment.");
        goto failure_free;
      }
      // Update the start.
      start_addr = virtaddr + (i * PAGE_SIZE);
      pfn_start = pfn_curr;
      idx_start = i;
    }
    pfn_prev = pfn_curr;
  }
  // Unpin the pages now.
  for (i = 0; i < page_count; i++) {
    put_page(pages[i]);
  }
  kfree(pages);
  // All done!
success:
  return SUCCESS;
failure_free:
  kfree(pages);
failure:
  return FAILURE;
}
EXPORT_SYMBOL(tyche_internal_register_mmap);

int tyche_register_mmap(driver_domain_t* dom, usize virtaddr, usize vsize)
{
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  // Check we have the lock on the domain.
  CHECK_WLOCK(dom, failure);

  // Nothing to do if size is null.
  if (vsize == 0) {
    goto success;
  }
  // Call the internal function.
  if (tyche_internal_register_mmap(&(dom->raw_segments), virtaddr, vsize)
      != SUCCESS) {
    ERROR("Unable to do the internal register mmap");
    goto failure;
  }

success:
  return SUCCESS;
failure:
  return FAILURE;
}

static segment_t* create_segment(usize va, usize hpa, usize size) {
  segment_t *segment = kmalloc(sizeof(segment_t), GFP_KERNEL);
  if (segment == NULL) {
    ERROR("Unable to allocate a segment");
    goto failure;
  }
  memset(segment, 0, sizeof(segment_t));
  segment->va = va;
  segment->pa = hpa;
  segment->size = size;
  segment->state = DRIVER_NOT_COMMITED;
  dll_init_elem(segment, list);
  return segment;
failure:
  return NULL;
}

static int translate_gpa_hpas(segment_list_t* res, usize va, usize gpa, usize size)
{
  usize curr_size = size, curr_gpa = gpa, curr_va = va;
  if (res == NULL) {
    ERROR("Result is null");
    goto failure;
  }
  dll_init_list(res);
  do {
    usize hpa = 0, hpa_size = 0;
    segment_t* seg = NULL;
    if (tyche_get_hpa(curr_gpa, curr_size, &hpa, &hpa_size) != SUCCESS) {
      ERROR("Call to monitor get hpa failed");
      goto failure_free;
    }
    seg = create_segment(curr_va, hpa, hpa_size);
    if (seg == NULL) {
      ERROR("Unable to allocate segment");
      goto failure_free;
    }
    // Add the segment.
    dll_add(res, seg, list);
    if (curr_size < hpa_size) {
      ERROR("curr size is smaller than hpa_size")
      goto failure_free;
    }
    curr_size -= hpa_size;
    curr_va += hpa_size;
    curr_gpa += hpa_size;
  } while(curr_size > 0);
  return SUCCESS;
failure_free:
  while(!dll_is_empty(res)) {
    segment_t* seg = res->head;
    dll_remove(res, seg, list);
    kfree(seg);
  }
failure:
  return FAILURE;
}

static int add_single_raw_segment(segment_list_t* segments, segment_t* segment)
{
  segment_t* curr = NULL;
  // The list is empty.
  if (dll_is_empty(segments)) {
    dll_add(segments, segment, list);
    goto finish;
  }
  // The list is not empty, we look for the right spot.
  dll_foreach(segments, curr, list) {
    if (dll_overlap(curr->va, (curr->va + curr->size),
          segment->va, (segment->va + segment->size))) {
      goto failure;
    }
    // curr is last and we come after..
    if (curr->va + curr->size <= segment->va && curr->list.next == NULL) {
      dll_add_after(segments, segment, list, curr);
      break;
    }

    if ((segment->va + segment->size) <= curr->va) {
      dll_add_before(segments, segment, list, curr);
      break;
    }
  }

  // We failed to insert.
  if (curr == NULL) {
    ERROR("Unable to find the correct position in the queue");
    goto failure;
  }

finish:
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_add_raw_segment(
    segment_list_t *segments,
    usize va,
    usize pa,
    usize size)
{
  segment_list_t to_add;
  if (segments == NULL) {
    ERROR("Provided domain is null.");
    goto failure;
  }
  if (translate_gpa_hpas(&to_add, va, pa, size) != SUCCESS) {
    ERROR("Failure to translate gpa to hpa");
    goto failure;
  }

  while(!dll_is_empty(&to_add)) {
    segment_t* seg = to_add.head;
    dll_remove(&to_add, seg, list);
    if (add_single_raw_segment(segments, seg) != SUCCESS) {
      ERROR("Failure to add one segment.");
      kfree(seg);
      goto failure_free;
    }
  }
  // All done.
  return SUCCESS;
failure_free:
  while(!dll_is_empty(&to_add)) {
    segment_t* seg = to_add.head;
    dll_remove(&to_add, seg, list);
    kfree(seg);
  }
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_add_raw_segment);

int driver_get_physoffset_domain(driver_domain_t *dom, usize vaddr, usize* phys_offset)
{
  segment_t *seg = NULL;
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

  if (dll_is_empty(&(dom->raw_segments)) && dll_is_empty(&(dom->segments))) {
    ERROR("The domain %p has not been initialized, call mmap first!", dom);
    goto failure;
  }
  // Check the raw segments.
  dll_foreach(&(dom->raw_segments), seg, list) {
    if (seg->va <= vaddr && ((seg->va + seg->size) > vaddr)) {
      *phys_offset = seg->pa + (vaddr - seg->va);
      return SUCCESS;
    }
  }
  // Check the segments.
  dll_foreach(&(dom->segments), seg, list) {
    if (seg->va <= vaddr && ((seg->va + seg->size) > vaddr)) {
      *phys_offset = seg->pa + (vaddr - seg->va);
      return SUCCESS;
    }
  }
  ERROR("Failure to find the right memslot %llx.\n", vaddr);
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
  segment_t* raw = NULL;
  usize curr_vaddr = vstart, curr_size = size;
  // The list of segments we are creating.
  dll_list(segment_t, segments);
  dll_init_list(&segments);

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
  /// We allow arbitrary regions inside the raw segment to be mprotected
  /// out-of-order (NEW). One region might span several raw ones, 
  /// with different PAs. The algorithm carves out the correct pieces one by one
  /// and creates a list of segments to be added to the dom->segments.
  if (dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain %p doesn't have mmaped memory.", dom);
    goto failure;
  }

  // Find the right part of the raw segments and start carving.
  raw = dom->raw_segments.head;
  while(raw != NULL && curr_size != 0) {
    usize raw_end = raw->va + raw->size;
    if (!((raw->va <= curr_vaddr) && (raw_end > curr_vaddr))) {
      // Not the right one.
      goto next_iter;
    }
    
    // Three cases are possible.
    // 1. full overlap with optional remainder.
    //    [xxxxxxx]
    //    [yyyyyyy]
    // 2. Left overlap
    //    [xxxxxxx]
    //    [yyyy]
    // 3. Right overlap with optional remainder.
    //    [xxxxxxxx]
    //          [yyy----]
    if (raw->va == curr_vaddr) {
      segment_t* seg = kmalloc(sizeof(segment_t), GFP_KERNEL);
      if (seg == NULL) {
        ERROR("Unable to allocate new segment");
        goto failure;
      }
      memset(seg, 0, sizeof(segment_t));
      seg->va = curr_vaddr;
      seg->pa = raw->pa;
      seg->flags = flags;
      seg->tpe = tpe;
      seg->alias = alias;
      seg->state = DRIVER_NOT_COMMITED;
      dll_init_elem(seg, list);
      dll_add(&segments, seg, list);
      // Is the raw segment completely consumed?
      if (raw->size <= curr_size) {
        segment_t* next = raw->list.next;
        // Update the pointers.
        curr_size -= raw->size;
        curr_vaddr += raw->size;
        seg->size = raw->size;
        dll_remove(&(dom->raw_segments), raw, list);
        kfree(raw);
        raw = next; 
        // Skip the update of raw.
        continue;
      } else if (raw->size > curr_size) {
        // Update the current raw segment.
        raw->va += curr_size;
        raw->pa += curr_size;
        raw->size -= curr_size;
        // Update the pointers.
        curr_vaddr += curr_size;
        seg->size = curr_size;
        curr_size = 0;
      }
    } else {
      // Split the current segment into two.
      usize diff = curr_vaddr - raw->va;
      segment_t* split = kmalloc(sizeof(segment_t), GFP_KERNEL);
      if (split == NULL) {
        ERROR("Unable to allocate the split segment.");
        goto failure;
      }
      memset(split, 0, sizeof(segment_t));
      dll_init_elem(split, list);
      split->va = curr_vaddr;
      split->pa = raw->pa + diff; 
      split->size = raw->size - diff;
      split->state = DRIVER_NOT_COMMITED;
      // Update raw.
      raw->size = diff;
      // Add the new segment to queue.
      dll_add_after(&(dom->raw_segments), split, list, raw);
      goto next_iter;
    }

  next_iter:
    raw = raw->list.next;
  } 

  if ((curr_vaddr != vstart + size) || (curr_size != 0)) {
    ERROR("Something went wrong during the mapping\n"
        "curr_vaddr: %llx, curr_size: %llx\n"
        "expected addr: %llx", curr_vaddr, curr_size, vstart + size);
    goto failure;
  }

  // Add the segments. They are ordered, we need to find where to put them.
  // Easy case:
  if (dll_is_empty(&(dom->segments))) {
    dom->segments.head = segments.head;
    dom->segments.tail = segments.tail;
    return SUCCESS;
  }

  // Find the right spot.
  dll_foreach(&(dom->segments), raw, list) {
    // We are too far.
    if (raw->va > vstart) {
      raw = NULL;
      break;
    }

    // Next one is null or greater than our start.
    if (raw->list.next == NULL || 
        (raw->list.next != NULL && raw->list.next->va > vstart)) {
      break;
    }
  }

  // Add everything to the head.
  if (raw == NULL) {
    segment_t* prev_head = dom->segments.head;
    dom->segments.head = segments.head;
    prev_head->list.prev = segments.tail;
    segments.tail->list.next = prev_head;
  } else {
    // Add everything after raw.
    segment_t* prev_next = raw->list.next;
    raw->list.next = segments.head;
    segments.head->list.prev = raw;
    segments.tail->list.next = prev_next;
    if (prev_next != NULL) {
      prev_next->list.prev = segments.tail;
    } else {
      // Update the segments tail.
      dom->segments.tail = segments.tail;
    }
  }

  /*if (driver_tyche_check_coalesce(dom, false) != SUCCESS) {
    ERROR("Problem coalescing non-raw segments.");
    goto failure;
  }*/

  DEBUG("Mprotect success  start: %llx, end: %llx",
      vstart, vstart + size);
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
  //TODO disable this for now.
  //return tyche_set_self_core_config(field, value);
  return 0;
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
    ERROR("The domain still has raw segments");
    dump_list(&(dom->raw_segments));
    //goto failure;
  }
  if (dll_is_empty(&dom->segments)) {
    ERROR("Missing segments for domain %p", dom);
    goto failure;
  }

 /* LOG("Dumping segments.");
  dll_foreach(&(dom->segments), segment, list) {
    LOG("Segment [addr: %llx, size: %llx, pa: %llx]", segment->va, segment->size, segment->pa);
  }
  segment = NULL;*/
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
          ERROR("Unable to grant segment %llx -- %llx {%x} | pa: %llx alias: %llx", segment->va,
              segment->size, segment->flags, segment->pa, segment->alias);
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
      case CONFIDENTIALIZABLE:
        if (grant_shared_region(dom->domain_id,
              segment->pa,
              segment->size,
              segment->flags,
              segment->alias) != SUCCESS) {
          ERROR("Unable to share confidentializable segment %llx -- %llx {%x}",
              segment->pa, segment->pa + segment->size, segment->flags);
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
  /*if (!dll_is_empty(&(dom->raw_segments))) {
    ERROR("The domain still has raw segments at commit time");
    goto failure;
  }*/
  if (dll_is_empty(&dom->segments)) {
    //ERROR("WARNING: the domain %p has no segment.", dom);
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

static exit_reason_t convert_exit_reason(usize exit[TYCHE_EXIT_FRAME_SIZE]) {
#if defined(CONFIG_X86) || defined(__x86_64__)
  /// VM_EXIT_REASON index.
  switch (exit[4]) {
    case EXIT_REASON_EPT_VIOLATION:
    case EXIT_REASON_EPT_MISCONFIG:
      return MEM_FAULT;
    case EXIT_REASON_EXCEPTION_NMI:
      return EXCEPTION;
    case EXIT_REASON_EXTERNAL_INTERRUPT:
      return INTERRUPT;
    case EXIT_REASON_PREEMPTION_TIMER:
      return TIMER;
    case DOMAIN_REVOKED:
      return REVOKED;
    default:
      return UNKNOWN;
  }
#elif defined(CONFIG_RISCV) || defined(__riscv)
  return UNKNOWN;
#endif
  return UNKNOWN;
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


int driver_switch_domain(driver_domain_t * dom, msg_switch_t* params) {
  usize exit_frame[TYCHE_EXIT_FRAME_SIZE] = {0};
  usize gp_frame[TYCHE_GP_REGS_SIZE] = {0};
  int local_cpuid = 0;
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  if (params == NULL) {
    ERROR("Switch received a null param, that's unexpected.");
    goto failure;
  }
  // Expects the domain to be R-locked.
  CHECK_RLOCK(dom, failure);

  if (params->core >= ENTRIES_PER_DOMAIN) {
    ERROR("Invalid core.");
    goto failure;
  }
  if ((dom->configs[TYCHE_CONFIG_CORES] & (1 << params->core)) == 0 ||
      dom->contexts[params->core] == NULL) {
    ERROR("Invalid core.");
    goto failure;
  }

  // Lock the core.
  down_write(&(dom->contexts[params->core]->rwlock));

  // This disables preemption to guarantee we remain on the same core after the
  // check.
  local_cpuid = get_cpu();
  // Check we are on the right core.
  if (params->core != local_cpuid) {
    ERROR("Attempt to switch on core %lld from cpu %d", params->core, local_cpuid);
    goto failure_unlock;
  }

  // LOCK THE CORE CONTEXT.
  // Hold the lock until we return from the switch.

  // Let's flush the caches.
  if (flush_caches(dom, params->core) != SUCCESS) {
    ERROR("Unable to flush caches.");
    goto failure_unlock;
  }

  // We can clear the cache now.
  cache_clear(&(dom->contexts[params->core]->cache), 1);

  // In case there is a delta, we should tell the linux watchdog to backoff.
  // This will avoid receiving spurious NMIs in the child.
  if (params->delta != 0) {
    touch_nmi_watchdog();
  }

  DEBUG("About to try to switch to domain %lld", dom->domain_id);
  params->error = 0;
  if (switch_domain(dom->domain_id, params->delta, exit_frame, local_cpuid) != SUCCESS) {
    params->error = convert_exit_reason(exit_frame);
    if (params->error == REVOKED) {
      ERROR("The domain has been revoked!");
      // We only have a read lock BUT all threads will try to write
      // the same value to this field. Anyone trying to do another operation
      // will have to acquire the write lock and is therefore blocked.
      dom->state = DRIVER_DEAD;
    } else {
      ERROR("Error(%d) in switch to domain %p", params->error, dom->handle);
    }
    goto failure_unlock;
  }

  if (update_set_exit(dom, params->core, exit_frame) != SUCCESS) {
    ERROR("Unable to update the exit frame.");
    goto failure_unlock;
  }

  // Provide the exit information.
  params->error = convert_exit_reason(exit_frame);

  // Get the gp registers.
  // TODO(aghosn) See if it's really necessary or not.
  if (read_gp_domain(dom->domain_id, params->core, gp_frame) != SUCCESS) {
    ERROR("Unable to read the domain's general purpose registers.");
    goto failure_unlock;
  }
  if (update_set_gp(dom, params->core, gp_frame) != SUCCESS) {
    ERROR("Unable to set the domain's general purpose registers.");
    goto failure_unlock;
  }

  // Reenable the preemption.
  put_cpu();
  // UNLOCK THE CORE CONTEXT.
  up_write(&(dom->contexts[params->core]->rwlock));
  return SUCCESS;
failure_unlock:
  put_cpu();
  up_write(&(dom->contexts[params->core]->rwlock));
failure:
  return FAILURE;
}
EXPORT_SYMBOL(driver_switch_domain);

int tyche_free_memory(segment_list_t* to_free)
{
  segment_t* segment = NULL;
  int i = 0;
  if (to_free == NULL) {
    // Nothing to do.
    goto failure;
  }
  // Delete the memory mappings.
  while(!dll_is_empty(to_free)) {
    segment = dll_head(to_free);
    dll_remove(to_free, segment, list);
    for (i = 0; i < (segment->size / PAGE_SIZE); i++) {
      char* mem = ((char*) segment->va) + i * PAGE_SIZE;
      ClearPageReserved(virt_to_page((unsigned long) mem));
    }
    free_pages_exact((void*) (segment->va), segment->size);
    kfree(segment);
    segment = NULL;
  }

  return SUCCESS;
failure:
  return FAILURE;
}
EXPORT_SYMBOL(tyche_free_memory);

int driver_delete_domain(driver_domain_t *dom)
{
  segment_t* segment = NULL;
  if (dom == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  /// We cannot delete if we do not have exclusive access to the domain.
  CHECK_WLOCK(dom, failure);
  if (dom->domain_id == UNINIT_DOM_ID || dom->state == DRIVER_DEAD) {
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
    dll_remove(&(dom->segments), segment, list);
    kfree(segment);
    segment = NULL;
  }

  if (tyche_free_memory(&(dom->to_free_on_delete)) != SUCCESS) {
    ERROR("Unable to free the reserved pages.");
    ERROR("Keep going with the deallocation to avoid memory leaks");
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
  memory_access_right_t basic_flags = flags & MEM_ACCESS_RIGHT_MASK_SEWRCA;
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
  pipe->flags = flags;
  dll_init_list(&(pipe->actives));
  dll_init_list(&(pipe->revokes));
  dll_init_elem(pipe, list);
  if (cut_region(phys_addr, size, basic_flags, &orig, &orig_revoke) != SUCCESS) {
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
  memory_access_right_t send_access;
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
  send_access = pipe->flags & MEM_ACCESS_RIGHT_MASK_VCH;
  dll_remove(&(pipe->actives), to_send, list);
  dll_remove(&(pipe->revokes), to_revoke, list);

  // We can free the pipe.
  if (dll_is_empty(&(pipe->actives)) && dll_is_empty(&(pipe->revokes))) {
    dll_remove(&(state.pipes), pipe, list);
    kfree(pipe);
    pipe = NULL;
  }

  if (send_region(domain->domain_id, to_send, to_revoke, send_access) != SUCCESS) {
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
