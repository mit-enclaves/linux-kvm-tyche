#ifndef __CONTALLOC_IOCTL_H__
#define __CONTALLOC_IOCTL_H__

#include <linux/fs.h>
#include <linux/mm_types.h>

// —————————————————————— Registration/Unregistration ——————————————————————— //
int contalloc_register(void);
void contalloc_unregister(void);

// —————————————————————————————————— API ——————————————————————————————————— //
int contalloc_open(struct inode *inode, struct file *file);
int contalloc_close(struct inode *inode, struct file *file);
long contalloc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int contalloc_mmap(struct file *, struct vm_area_struct *);

#endif /*__CONTALLOC_IOCTL_H__*/
