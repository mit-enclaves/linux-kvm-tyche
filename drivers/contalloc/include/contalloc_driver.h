#ifndef __INCLUDE_CONTALLOC_DRIVER_H__
#define __INCLUDE_CONTALLOC_DRIVER_H__

#ifdef _IN_MODULE
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

// ————————————————————————————————— Types —————————————————————————————————— //
typedef u64 usize;

// ———————————————————— Constants Defined in the Module ————————————————————— //
#define TE_READ ((uint64_t)MEM_READ)
#define TE_WRITE ((uint64_t)MEM_WRITE)
#define TE_EXEC ((uint64_t)MEM_EXEC)
#define TE_SUPER ((uint64_t)MEM_SUPER)
#define TE_DEFAULT ((uint64_t)(TE_READ | TE_WRITE | TE_EXEC))

// —————————————————————— Types Exposed by the Library —————————————————————— //
typedef enum segment_type_t {
	SHARED = 0,
	CONFIDENTIAL = 1,
	SHARED_REPEAT = 2,
	CONFIDENTIAL_REPEAT = 3,
} segment_type_t;

// ———————————————————————————————— Messages ———————————————————————————————— //

/// Default message used to communicate with the driver.
typedef struct {
	usize virtaddr;
	usize physoffset;
} msg_info_t;

// ———————————————————————————— Tyche IOCTL API ————————————————————————————— //
// @deprecated, use open.
#define CONTALLOC_GET_PHYSOFFSET _IOR('a', 'c', msg_info_t *)

#endif
