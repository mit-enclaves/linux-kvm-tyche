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
	usize size;
} msg_t;

// ———————————————————————————— Tyche IOCTL API ————————————————————————————— //
// @deprecated, use open.
#define CONTALLOC_GET_PHYSOFFSET _IOWR('a', 'c', msg_t *)
#define CONTALLOC_REGISTER_MMAP _IOWR('a', 'd', msg_t *)

#endif
