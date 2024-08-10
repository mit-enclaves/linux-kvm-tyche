#ifndef __CONTALLOC_IOCTL_H__
#define __CONTALLOC_IOCTL_H__

#include "allocs.h"
#include <linux/fs.h>
#include <linux/mm_types.h>

typedef struct {
	int (*driver_mmap_alloc)(cont_alloc_t *alloc,
				 struct vm_area_struct *vma);

} contalloc_backend_t;

extern contalloc_backend_t global_alloc_backend;

void init_regular_backend(contalloc_backend_t *backend);
void init_coloring_backend(contalloc_backend_t *backend);

// —————————————————————— Registration/Unregistration ——————————————————————— //
int contalloc_register(void);
void contalloc_unregister(void);

// —————————————————————————————————— API ——————————————————————————————————— //
long contalloc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif /*__CONTALLOC_IOCTL_H__*/
