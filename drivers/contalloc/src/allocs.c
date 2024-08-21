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
#include "common_log.h"
#include "allocs.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

static dll_list(cont_alloc_t, allocs);

// ———————————————————————————— Helper Functions ———————————————————————————— //

cont_alloc_t* find_alloc(driver_handle_t handle)
{
  cont_alloc_t* alloc = NULL;
  dll_foreach((&allocs), alloc, list) {
    if (alloc->handle == handle) {
      break;
    }
  }
  if (alloc == NULL) {
    goto failure;
  }
  if (alloc->pid != current->tgid) {
    ERROR("Attempt to access alloc %p from wrong pid", handle);
    ERROR("Expected pid: %d, got: %d", alloc->pid, current->tgid);
    goto failure;
  }
  return alloc;
failure:
  return NULL;
}


// ——————————————————————————————— Functions ———————————————————————————————— //

void contalloc_init_allocs(void)
{
  dll_init_list((&allocs));
}


int contalloc_create_alloc(driver_handle_t handle)
{
  cont_alloc_t* alloc = find_alloc(handle);
  if (alloc != NULL) {
    ERROR("The alloc with handle %p already exists.", handle);
    goto failure;
  }
  alloc = kmalloc(sizeof(cont_alloc_t), GFP_KERNEL);
  if (alloc == NULL) {
    ERROR("Failed to allocate a new cont_alloc_t structure.");
    goto failure;
  }
  memset(alloc, 0, sizeof(cont_alloc_t));
  // Set up the structure.
  alloc->pid = current->tgid;
  alloc->handle = handle;
  dll_init_list(&(alloc->raw_segments));
  dll_init_elem(alloc, list);

  // Add the alloc to the list.
  dll_add((&allocs), alloc, list);

  return SUCCESS;
failure:
  return FAILURE;
}

int contalloc_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma)
{
  if (vma == NULL || alloc->handle == NULL) {
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
  if (alloc == NULL) {
    ERROR("Unable to find the right alloc.");
    goto failure;
  }
  if (driver_tyche_mmap(&(alloc->raw_segments), vma) != SUCCESS) {
    ERROR("Unable to mmap vma 0x%lx - 0x%lx", vma->vm_start, vma->vm_end);
    goto failure;
  }
  // We do not coalesce in kvm.
  return SUCCESS;
failure:
  return FAILURE;
}

int contalloc_get_physoffset_alloc(cont_alloc_t *alloc, usize vaddr, usize* phys_offset)
{
  mmem_t *seg = NULL;
  if (phys_offset == NULL) {
    ERROR("The provided phys_offset variable is null.");
    goto failure;
  }
  if (alloc == NULL) {
    ERROR("The provided alloc is NULL.");
    goto failure;
  }
  if (dll_is_empty(&(alloc->raw_segments))) {
    ERROR("The alloc %p has not been initialized, call mmap first!", alloc);
    goto failure;
  }
  dll_foreach(&(alloc->raw_segments), seg, list) {
    if (seg->va <= vaddr && ((seg->va + seg->size) > vaddr)) {
      *phys_offset = seg->pa + (vaddr - seg->va);
      return SUCCESS;
    }
  }
  ERROR("Failure to find the right memslot %lld.\n", vaddr);
failure:
  return FAILURE;
}

int contalloc_delete_alloc(cont_alloc_t *alloc)
{
  mmem_t* segment = NULL;
  usize size = 0;
  if (alloc == NULL) {
    ERROR("The alloc is null.");
    goto failure;
  }
  // Delete all segments;
  while(!dll_is_empty(&(alloc->raw_segments))) {
    segment = dll_head(&(alloc->raw_segments));
    size += segment->size;
    dll_remove(&(alloc->raw_segments), segment, list);
    //TODO: this creates a bug if munmap was called from userspace.
    //Let's just skip it for now.
    /*if (alloc->handle != NULL) {
      free_pages_exact(phys_to_virt((phys_addr_t)(segment->pa)), size);
    }*/
    kfree(segment);
    segment = NULL;
  }

  dll_remove(&allocs, alloc, list);
  kfree(alloc);
  return SUCCESS;
failure:
  return FAILURE;
}
