#include "color_bitmap.h"
#include "dll.h"
#include "linux/bitmap.h"
#include "linux/bitops.h"
#include "linux/gfp_types.h"
#include "src/coloring_backend.h"
#include "src/contalloc_ioctl.h"
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

#include "tyche_api.h"

//luca: this is the driver that kvm uses. the one before was the custom sdk stuff

// ———————————————————————————————— Globals ————————————————————————————————— //

//luca: probably tracks active allocations
static dll_list(cont_alloc_t, allocs);

// ———————————————————————————— Helper Functions ———————————————————————————— //

cont_alloc_t *find_alloc(driver_handle_t handle)
{
	cont_alloc_t *alloc = NULL;
	dll_foreach((&allocs), alloc, list)
	{
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

/**
 * @brief Returns a deepcopy the segment
 * 
 * @param handle  id of the allocating domain
 * @param start_gva start of the allocation
 * @param out_segment Callee allocated output param, free with mmem_t_free
 * @return int SUCCESS or FAILURE
 */
int contalloc_get_segment(driver_handle_t handle, uint64_t start_gva, mmem_t* out_segment) {
	mmem_t* seg = NULL;
	cont_alloc_t* alloc;
	alloc = find_alloc(handle);
	if( !alloc) {
		ERROR("did not find entry for handle 0x%llx", (uint64_t)handle);
		return FAILURE;
	}
	dll_foreach(&(alloc->raw_segments), seg, list)
	{
		if( seg->start_gva == start_gva) {
			mmem_t_deepcopy(seg, out_segment);
			return SUCCESS;
		}
	}
	
	ERROR("handle 0x%llx : no raw segment  with start GVA 0x%llx", (uint64_t)handle, start_gva);
	return FAILURE;
}

//luca: creates new entry in global var `allocs` to track any upcoming allocations for this caller
int contalloc_create_alloc(driver_handle_t handle)
{
	cont_alloc_t *alloc = find_alloc(handle);
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

void mmem_t_init(mmem_t *mmem, size_t color_count)
{
	memset(mmem, 0, sizeof(mmem_t));
	color_bitmap_init(&(mmem->color_bm));

	mmem->_fragment_capacity = 1 << 4;
	mmem->fragments =
		kmalloc(sizeof(alloc_fragment_t) * mmem->_fragment_capacity,
			GFP_KERNEL);
}

void mmem_t_add_fragment(mmem_t *mmem, alloc_fragment_t fragment)
{
	//increase array size if we ran out of space
	if (mmem->fragment_count == mmem->_fragment_capacity) {
		mmem->_fragment_capacity = mmem->_fragment_capacity * 2;

		mmem->fragments =
			krealloc(mmem->fragments,
				 mmem->_fragment_capacity *
					 sizeof(mmem->fragments[0]),
				 GFP_KERNEL);
	}
	//store addrs
	mmem->fragments[mmem->fragment_count] = fragment;
	
	mmem->fragment_count += 1;
	mmem->size += fragment.size;

	//store color
	color_bitmap_set(&(mmem->color_bm), fragment.color_id, true);
}

int mmem_t_pop_from_front(mmem_t* self, size_t remove_count) {
	alloc_fragment_t* updated;
	size_t removed_bytes,idx;
	if( remove_count > self->fragment_count) {
		ERROR("requested to remove %lu elements but have only %lu", remove_count, self->fragment_count);
		return FAILURE;
	}

	removed_bytes = 0;
	for(idx = 0; idx < remove_count; idx++) {
		removed_bytes += self->fragments[idx].size;
	}
	updated = kmalloc(self->_fragment_capacity * sizeof(alloc_fragment_t), GFP_KERNEL);
	memcpy(updated, self->fragments+remove_count, sizeof(alloc_fragment_t) * (self->fragment_count - remove_count));
	kfree(self->fragments);
	self->fragments = updated;
	self->fragment_count -= remove_count;
	self->size -= removed_bytes;

	//rebuild color bitmap
	color_bitmap_set_all(&(self->color_bm), false);
	for(idx = 0; idx < self->fragment_count; idx++) {
		color_bitmap_set(&(self->color_bm), self->fragments[idx].color_id, true);
	}
	return SUCCESS;
}
void mmem_t_deepcopy(mmem_t *source, mmem_t *target) {
	target->start_gpa = source->start_gpa;
	target->start_gva = source->start_gva;
	target->size = source->size;

	if(source->_fragment_capacity == 0) {
		FAIL();
	}
	if(source->fragment_count > source->_fragment_capacity) {
		FAIL();
	}
	target->fragments = kmalloc(sizeof(alloc_fragment_t)* source->_fragment_capacity, GFP_KERNEL);
	if(!target->fragments) {
		FAIL();
	}
	memcpy(target->fragments, source->fragments, sizeof(alloc_fragment_t)*source->fragment_count);
	target->fragment_count = source->fragment_count;
	target->_fragment_capacity = source->_fragment_capacity;

	target->color_bm = source->color_bm;

	memset(&(target->list), 0, sizeof(target->list));
}

void mmem_t_free(mmem_t mmem)
{
	kfree(mmem.fragments);
}

static int driver_add_raw_segment(cont_alloc_t *alloc, mmem_t *segment)
{
	if (alloc == NULL) {
		ERROR("Provided alloc is null.");
		goto failure;
	}
	dll_init_elem(segment, list);
	dll_add(&(alloc->raw_segments), segment, list);
	return SUCCESS;
failure:
	return FAILURE;
}

int contalloc_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma)
{
	void *allocation = NULL;
	usize size = 0;
	int order = 0;
	mmem_t *segment = NULL;
	alloc_fragment_t fragment;

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

	// Allocate a contiguous memory region.
	size = vma->vm_end - vma->vm_start;
	order = get_order(size);
	if (order >= MAX_ORDER) {
		ERROR("The requested size of: %llx has order %d while max order is %d",
		      size, order, MAX_ORDER);
	}
	allocation = alloc_pages_exact(size, GFP_KERNEL);
	if (allocation == NULL) {
		ERROR("Alloca pages exact failed to allocate the pages %llx.",
		      size);
		goto failure;
	}
	memset(allocation, 0, size);
	// Prevent pages from being collected.
	for (int i = 0; i < (size / PAGE_SIZE); i++) {
		char *mem = ((char *)allocation) + i * PAGE_SIZE;
		SetPageReserved(virt_to_page((unsigned long)mem));
	}

	DEBUG("The phys address %llx, virt: %llx",
	      (usize)virt_to_phys(allocation), (usize)allocation);
	if (vm_iomap_memory(vma, virt_to_phys(allocation), size)) {
		ERROR("Unable to map the memory...");
		goto fail_free_pages;
	}

	segment = kmalloc(sizeof(mmem_t), GFP_KERNEL);
	 

	//call to tyche sm to get the hpa range that backs this allocation
	if( tyche_get_hpas(virt_to_phys(allocation), size, &fragment.start_hpa, &fragment.end_hpa) ) {
		ERROR("failed to get HPAs for allocation");
		goto fail_free_pages;
	}
	//TODO:make configureable
	mmem_t_init(segment, 64);
	fragment.color_id = 0;
	fragment.gpa = virt_to_phys(allocation);
	fragment.size = size;
	
	mmem_t_add_fragment(segment, fragment);
	//luca: VMA segment of Linux's memory management abstractions
	if (driver_add_raw_segment(alloc,segment) != SUCCESS) {
		ERROR("Unable to allocate a segment");
		goto fail_free_pages;
	}
	return SUCCESS;
fail_free_pages:
	free_pages_exact(allocation, size);
failure:
	return FAILURE;
}

//TODO: this broken with coloring
int driver_get_physoffset_alloc(cont_alloc_t *alloc, usize slot_id,
				usize *phys_offset)
{
	mmem_t *seg = NULL;
	usize slot_counter = 0;
	if (phys_offset == NULL) {
		ERROR("The provided phys_offset variable is null.");
		goto failure;
	}
	if (alloc == NULL) {
		ERROR("The provided alloc is NULL.");
		goto failure;
	}
	if (dll_is_empty(&(alloc->raw_segments))) {
		ERROR("The alloc %p has not been initialized, call mmap first!",
		      alloc);
		goto failure;
	}
	dll_foreach(&(alloc->raw_segments), seg, list)
	{
		if (slot_counter == slot_id) {
			*phys_offset = seg->start_gpa;
			return SUCCESS;
		}
		slot_counter++;
	}
	ERROR("Failure to find the right memslot %lld.\n", slot_id);
failure:
	return FAILURE;
}

int contalloc_delete_alloc(cont_alloc_t *alloc)
{
	mmem_t *segment = NULL;
	usize size = 0;
	if (alloc == NULL) {
		ERROR("The alloc is null.");
		goto failure;
	}
	// Delete all segments;
	while (!dll_is_empty(&(alloc->raw_segments))) {
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

void init_regular_backend(contalloc_backend_t *backend)
{
	backend->driver_mmap_alloc = contalloc_mmap_alloc;
}