#ifndef __INCLUDE_CONTALLOC_DRIVER_H__
#define __INCLUDE_CONTALLOC_DRIVER_H__

#ifdef _IN_MODULE
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#include "common.h"

// ———————————————————————————————— Messages ———————————————————————————————— //

/// Default message used to communicate with the driver.
typedef struct {
	usize virtaddr;
	usize physoffset;
} msg_t;

typedef struct {
	// Number of callers used for the callers allocations
	size_t used_colors;
} get_my_color_count_t;

typedef struct {
	// Globally valid if of the color
	uint64_t color_id;
	// GPA where this color is mapped in kernel space
	uint64_t start_gpa;
	// Number of bytes that are used from this color
	size_t used_bytes;
} user_color_info_t;

typedef struct {
	//Use CONTALLOC_GET_MY_COLOR_COUNT to get the correct size
	user_color_info_t *info;
	size_t info_len;
} get_my_color_info_t;

// ———————————————————————————— Tyche IOCTL API ————————————————————————————— //
// @deprecated, use open.
#define CONTALLOC_IOCTL_MAGIC 'a'
#define CONTALLOC_GET_PHYSOFFSET _IOWR(CONTALLOC_IOCTL_MAGIC, 'c', msg_t *)

#define CONTALLOC_GET_MY_COLOR_COUNT \
	_IOWR(CONTALLOC_IOCTL_MAGIC, 'd', get_my_color_count_t)

#define CONTALLOC_GET_MY_COLOR_INFO \
	_IOWR(CONTALLOC_IOCTL_MAGIC, 'd', get_my_color_info_t)

#endif
