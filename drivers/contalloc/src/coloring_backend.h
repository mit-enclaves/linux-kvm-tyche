#ifndef COLORING_BACKEND_H
#define COLORING_BACKEND_H

#include "allocs.h"
#include <linux/types.h>

typedef struct {
	/*GPA at which the mappings for the individual colors start
	this is marked as reserved memory in the E820 entries.
	Each color is mapped to contiguous GPAs. The `bytes_for_color`
	array contains the bytes for the individual colors
	Due to memory reserved early in the boot process, the size
	of the colors might differ sligthly
	*/
	uint64_t start_gpa;
	// Color id for the first color. Remaining colors are assumed to have
	// contiguous ids
	uint64_t id_first_color;
	// array with the length of the individual colors in bytes
	size_t *bytes_for_color;
	// length of `bytes_for_color` array
	size_t bytes_for_color_len;
} coloring_info_t;

typedef struct {
	uint64_t color_id;
	uint64_t start_gpa;
	uint64_t bytes;
	uint64_t next_free_offset;
} color_state_t;

#define COLOR_UNUSED NULL
typedef struct {
	size_t color_count;
	//stores which entitiy uses this color. `COLOR_UNUSED` if free
	driver_handle_t *color_to_entity;

	color_state_t *color_state;
} coloring_backend_state_t;

int init_coloring_backend_state(coloring_info_t *coloring_info);

int driver_coloring_mmap_alloc(cont_alloc_t *alloc, struct vm_area_struct *vma);

uint64_t get_my_color_count(cont_alloc_t *alloc);
int get_my_color_info(cont_alloc_t *alloc, user_color_info_t *color_info,
		      size_t color_info_len);

#endif