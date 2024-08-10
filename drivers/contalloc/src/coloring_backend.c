#include "coloring_backend.h"
#include "allocs.h"
#include "asm-generic/bug.h"
#include "asm/bug.h"
#include "asm/page_types.h"
#include "asm/pgtable_types.h"
#include "color_bitmap.h"
#include "common_log.h"
#include "contalloc_driver.h"
#include "linux/gfp_types.h"
#include "linux/jbd2.h"
#include "linux/kvm_types.h"
#include "linux/sunrpc/msg_prot.h"
#include "linux/vmalloc.h"
#include "src/common.h"
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

#include "tyche_api.h"

static coloring_backend_state_t coloring_backend_state;

/**
 * @brief Return the number of colors reserved for this entity
 * 
 * @param alloc 
 * @return uint64_t number of reserved colors
 */
uint64_t get_my_color_count(cont_alloc_t *alloc)
{
	size_t idx;
	uint64_t color_count = 0;
	for (idx = 0; idx < coloring_backend_state.color_count; idx++) {
		if (coloring_backend_state.color_to_entity[idx] ==
		    alloc->handle) {
			color_count += 1;
		}
	}

	return color_count;
}

/**
 * @brief Populate color_info with the requested information.
 * 
 * @param alloc Handle for which we lookup the information
 * @param color_info Caller allocated. Use `get_my_color_count` the learn correct length
 * @param color_info_len len of color_info
 * @return int 0 on success
 */
int get_my_color_info(cont_alloc_t *alloc, user_color_info_t *color_info,
		      size_t color_info_len)
{
	size_t color_id;
	size_t color_info_idx = 0;
	coloring_backend_state_t *cbs = &coloring_backend_state;
	for (color_id = 0; color_id < coloring_backend_state.color_count;
	     color_id++) {
		if (cbs->color_to_entity[color_id] == alloc->handle) {
			if (color_info_idx > color_info_len) {
				return -1;
			}
			color_info[color_info_idx].color_id = color_id;
			color_info[color_info_idx].start_gpa =
				cbs->color_state[color_id].start_gpa;
			color_info[color_info_idx].used_bytes =
				cbs->color_state[color_id].next_free_offset;
			color_info_idx += 1;
		}
	}
	return 0;
}

/**
 * @brief Initializes the allocator state that tracks color usage
 * 
 * @param coloring_info 
 * @return int 0 on success
 */
int init_coloring_backend_state(coloring_info_t *coloring_info)
{
	size_t idx;
	uint64_t next_color_gpa;

	printk("%s:%d %s Have %lu colors, first color id %llu, start GPA %llu", __FILE__, __LINE__, __FUNCTION__, coloring_info->bytes_for_color_len, coloring_info->id_first_color, coloring_info->start_gpa);

	coloring_backend_state.color_count = coloring_info->bytes_for_color_len;

	coloring_backend_state.color_to_entity = kmalloc(
		sizeof(driver_handle_t) * coloring_backend_state.color_count,
		GFP_KERNEL);
	memset(coloring_backend_state.color_to_entity, 0,
	       sizeof(driver_handle_t) * coloring_backend_state.color_count);

	coloring_backend_state.color_state = kmalloc(
		sizeof(color_state_t) * coloring_backend_state.color_count,
		GFP_KERNEL);
	next_color_gpa = coloring_info->start_gpa;
	for (idx = 0; idx < coloring_backend_state.color_count;
	     idx++) {
		coloring_backend_state.color_state[idx].color_id =
			coloring_info->id_first_color + idx;
		coloring_backend_state.color_state[idx].start_gpa =
			next_color_gpa;
		coloring_backend_state.color_state[idx].bytes =
			coloring_info->bytes_for_color[idx];
		coloring_backend_state.color_state[idx].next_free_offset =
			0;

		next_color_gpa += coloring_info->bytes_for_color[idx];
	}

	return 0;
}

/**
 * @brief Try to reserve a new color for the caller
 * 
 * @param handle 
 * @return color_state_t* NULL if no colors are avilable, ptr to color state otherwise
 */
static color_state_t *reserve_new_color(driver_handle_t handle)
{
	size_t color_id;
	coloring_backend_state_t *cbs = &coloring_backend_state;

	for (color_id = 0; color_id < cbs->color_count; color_id++) {
		if (cbs->color_to_entity[color_id] == COLOR_UNUSED) {
			//assign color to caller's identity
			cbs->color_to_entity[color_id] = handle;
			return cbs->color_state + color_id;
		}
	}
	return NULL;
}

/**
 * @brief Check if caller has color with remaining memory and return it.
 * Otherwise, use `reserve_new_color` to request a new color
 * 
 * @param calling_entity 
 * @return color_state_t* NULL if all colors depleted
 */
static color_state_t *get_undepleted_color(driver_handle_t calling_entity)
{
	size_t color_id;
	coloring_backend_state_t *cbs = &coloring_backend_state;

	for (color_id = 0; color_id < cbs->color_count; color_id++) {
		//check if color is assigned to caller
		if (cbs->color_to_entity[color_id] == calling_entity) {
			//check if color has remaining memory
			if (cbs->color_state[color_id].next_free_offset <
			    cbs->color_state[color_id].bytes) {
				return cbs->color_state + color_id;
			}
		}
	}
	return NULL;
}

//TODO: this is duplicated with allocs.c . There was a weird bug when making this non static,
//as it also seems to be defined in drivers/tyche/src/domains.o:
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

/**
 * @brief Zero @bytes many bytes starting at @start_hpa
 * 
 */
static void memset_pyhs_range_zero(uint64_t start_hpa, size_t bytes) {
	unsigned long* pfns = NULL;
	void* kernel_mapping = NULL ;
	unsigned long pfn,start_pfn,offset;
	size_t page_count;
	offset = start_hpa & (PAGE_SIZE-1);
	start_pfn = start_hpa >> PAGE_SHIFT;
	//number of pages we need to map: mapping starts page down aligned, thus add offset to bytes
	//align up the value, since we need to any final page that we only partially use
	page_count = ALIGN(bytes+offset,PAGE_SIZE)/PAGE_SIZE;

	pfns = kmalloc(sizeof(unsigned long)*page_count, GFP_KERNEL);
	for(pfn = start_pfn; pfn < (start_pfn+page_count); pfn++) {
		pfns[pfn-start_pfn] = pfn;
	}

	kernel_mapping = vmap_pfn(pfns, page_count, PAGE_KERNEL);
	memset(((uint8_t*)kernel_mapping)+offset,0, bytes);

	vunmap(kernel_mapping);
	kfree(pfns);
}

/**
 * @brief Allocate memory ensuring that all used colors are exclusive to the allocation handle/caller entitity.
 * 
 * @param alloc 
 * @param vma 
 * @return int 0 on success
 */
int driver_coloring_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma)
{
	int64_t remaining_bytes;
	color_state_t *cur_color = NULL;
	int status;
	unsigned long vma_next_free_vaddr;
    mmem_t *segment = NULL;

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

	remaining_bytes = vma->vm_end - vma->vm_start;
	if ((remaining_bytes % PAGE_SIZE) != 0) {
		ERROR("allocation need to be page aligned for now");
		return -1;
	}
	vma_next_free_vaddr = vma->vm_start;
	//printk("%s:%d %s requested bytes 0x%llx, vma_next_free_vaddr 0x%lx\n", __FILE__, __LINE__, __FUNCTION__, remaining_bytes, vma_next_free_vaddr);

	segment = kmalloc(sizeof(mmem_t), GFP_KERNEL);
	mmem_t_init(segment, TYCHE_COLOR_COUNT);

	cur_color = get_undepleted_color(alloc->handle);
	while (remaining_bytes > 0) {
		int64_t useable_bytes_in_color;
		phys_addr_t allocation_start_gpa;
		int64_t allocation_size;
		alloc_fragment_t fragment;

		//printk("%s:%d %s using previous color\n", __FILE__, __LINE__, __FUNCTION__);

		//no current color or no more space in current color
		if (cur_color == NULL ||
		    (cur_color->next_free_offset == cur_color->bytes)) {
			cur_color = reserve_new_color(alloc->handle);
			if (cur_color == NULL) {
				ERROR("Out of memory");
				goto fail_free_pages;
			}
		}

		//printk("%s:%d %s color info: start_gpa 0x%llx next_free_offset 0x%llx\n", __FILE__, __LINE__, __FUNCTION__, cur_color->start_gpa, cur_color->next_free_offset);

		//Determine amount of mem that we can use from current color and update
		//free memory tracker of color
		useable_bytes_in_color =
			cur_color->bytes - cur_color->next_free_offset;
		//Case 1: Color has enough mem for allocation
		if (useable_bytes_in_color > remaining_bytes) {
			allocation_size = remaining_bytes;
			allocation_start_gpa = cur_color->start_gpa +
					       cur_color->next_free_offset;
			cur_color->next_free_offset += allocation_size;
			//printk("%s:%d %s color has enough mem, new next_free_offset is 0x%llx\n", __FILE__, __LINE__, __FUNCTION__, cur_color->next_free_offset);

		} else { //Case 2: Color does not have enough mem for allocation
			allocation_size = useable_bytes_in_color;
			allocation_start_gpa = cur_color->start_gpa +
					       cur_color->next_free_offset;
			cur_color->next_free_offset += allocation_size;
			//printk("%s:%d %s color does not have enough mem, only allocating 0x%llx out of requested 0x%llx bytes\n", __FILE__, __LINE__, __FUNCTION__, allocation_size, remaining_bytes);
		}

        if (segment->fragment_count == 0) {
			segment->start_gpa = allocation_start_gpa;
			segment->start_gva = vma_next_free_vaddr;
		}

		//call to tyche sm to get the hpa range that backs this allocation
		if( tyche_get_hpas(allocation_start_gpa, allocation_size, &fragment.start_hpa, &fragment.end_hpa) ) {
			ERROR("failed to get HPAs for allocation");
			goto fail_free_pages;
		}
		fragment.gpa = allocation_start_gpa;
		fragment.size = allocation_size;
		fragment.color_id = cur_color->color_id;

		mmem_t_add_fragment(segment, fragment);

		//temporary map mem in kern space and zero it before mapping it to userspace
		memset_pyhs_range_zero(fragment.gpa, fragment.size);

		printk("%s:%d %s Mapping GPA 0x%llx length 0x%llx to VMA at 0x%lx\n",
		       __FILE__, __LINE__, __FUNCTION__, allocation_start_gpa,
		       allocation_size, vma_next_free_vaddr);
		//Map memory to user space

		//the mmap call path already ensures that we hold the proper locks
		if ((status = remap_pfn_range(
			     vma, vma_next_free_vaddr,
			     allocation_start_gpa >> PAGE_SHIFT,
			     allocation_size, vma->vm_page_prot))) {
			ERROR("Failed to map to user, status %d", status);
			goto fail_free_pages;
		}

		vma_next_free_vaddr += allocation_size;
		remaining_bytes -= allocation_size;
	}



	if (driver_add_raw_segment(alloc, segment) != SUCCESS) {
		ERROR("Unable to store segment");
		goto fail_free_pages;
	}

	return SUCCESS;

fail_free_pages:
	if( segment != NULL ) {
        size_t idx;
        coloring_backend_state_t* cbs = &coloring_backend_state;

        //update allocator state
        for( idx = 0; idx < segment->fragment_count;idx++) {
            alloc_fragment_t* f = segment->fragments+idx;

            BUG_ON(cbs->color_state[f->color_id].next_free_offset < f->size);
            
            //assumption: we are the most recent allocation for this color
            BUG_ON((cbs->color_state[f->color_id].next_free_offset + cbs->color_state[f->color_id].start_gpa) != f->gpa);
            cbs->color_state[f->color_id].next_free_offset -= f->size;

            //if color completely free, mark it as available
            if( cbs->color_state[f->color_id].start_gpa == cbs->color_state[f->color_id].next_free_offset) {
                cbs->color_to_entity[f->color_id] = COLOR_UNUSED;
            }
        }
        mmem_t_free(*segment);
        kfree(segment);
    }
	ERROR("exiting driver_coloring_mmap_alloc through fail_free_pages");

failure:
	ERROR("exiting driver_coloring_mmap_alloc through failure");
	return FAILURE;
}

void init_coloring_backend(contalloc_backend_t *backend)
{
	backend->driver_mmap_alloc = driver_coloring_mmap_alloc;
}