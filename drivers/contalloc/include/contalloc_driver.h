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
} msg_info_t;

// ———————————————————————————— Tyche IOCTL API ————————————————————————————— //
// @deprecated, use open.
#define CONTALLOC_GET_PHYSOFFSET _IOWR('a', 'c', msg_info_t *)

#endif
