#include <linux/ioctl.h>
#include <linux/kernel.h>   /* printk() */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>

#include "common.h"
#include "common_log.h"
#include "allocs.h"
#define _IN_MODULE
#include "contalloc_driver.h"
#include "contalloc_ioctl.h"
#undef _IN_MODULE
// —————————————————————— Global Driver Configuration ——————————————————————— //
static char* device_name = "contalloc";
static char* device_class = "contalloc";
static char* device_region = "contalloc";

dev_t contalloc_dev = 0;
static struct cdev contalloc_cdev;
static struct class *contalloc_dev_class;

// ———————————————————————————— File Operations ————————————————————————————— //

// File operation structure
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .open           = contalloc_open,
        .release        = contalloc_close,
        .unlocked_ioctl = contalloc_ioctl,
        .mmap           = contalloc_mmap,
};

// ———————————————————————————— Driver Functions ———————————————————————————— //


int contalloc_register(void)
{
  // Allocating Major number
  if((alloc_chrdev_region(&contalloc_dev, 0, 1, device_region)) <0){
    ERROR("cannot allocate major number\n");
    return FAILURE;
  }
  LOG("Major = %d Minor = %d \n",MAJOR(contalloc_dev), MINOR(contalloc_dev));

  // Creating the cdev structure
  cdev_init(&contalloc_cdev, &fops);

  // Adding character device to the system.
  if ((cdev_add(&contalloc_cdev, contalloc_dev, 1)) < 0)
  {
    ERROR("Cannot add the device to the system.\n");
    goto r_class;
  }

  // Creating the struct class.
  if ((contalloc_dev_class = class_create(THIS_MODULE, device_class)) == NULL)
  {
    ERROR("Cannot create the struct class.\n");
    goto r_class;
  }

  // Creating the device.
  if ((device_create(contalloc_dev_class, NULL, contalloc_dev, NULL, device_name)) == NULL)
  {
    ERROR("Cannot create the Device 1\n");
    goto r_device;
  }

  driver_init_allocs();
  LOG("Tyche allocator driver registered!\n");
  trace_printk("Tyche driver initialized\n");
  return SUCCESS;

r_device:
  class_destroy(contalloc_dev_class);
r_class:
  unregister_chrdev_region(contalloc_dev, 1);
  return FAILURE;
}

void contalloc_unregister(void)
{
  device_destroy(contalloc_dev_class, contalloc_dev);
  class_destroy(contalloc_dev_class);
  cdev_del(&contalloc_cdev);
  unregister_chrdev_region(contalloc_dev, 1);
  LOG("Tyche allocator driver unregistered!\n");
}

// —————————————————————————————————— API ——————————————————————————————————— //

int contalloc_open(struct inode* inode, struct file* file)
{
  if (file == NULL) {
    ERROR("We received a Null file descriptor.");
    goto failure;
  }
  if (driver_create_alloc(file) != SUCCESS) {
    ERROR("Unable to create a new alloc");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int contalloc_close(struct inode* inode, struct file* handle)
{
  cont_alloc_t * alloc = find_alloc(handle);
   if (alloc == NULL || driver_delete_alloc(alloc) != SUCCESS) {
        ERROR("Unable to delete the alloc %p", handle);
        goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}


long contalloc_ioctl(struct file* handle, unsigned int cmd, unsigned long arg)
{
  msg_t info = {UNINIT_USIZE, UNINIT_USIZE};
  cont_alloc_t *alloc = find_alloc(handle);
  if (alloc == NULL) {
    ERROR("Unable to find the alloc %p!\n", handle);
    goto failure;
  }
  switch(cmd) {
    case CONTALLOC_GET_PHYSOFFSET:
      if (copy_from_user(&info, (msg_t*)arg, sizeof(msg_t))) {
        ERROR("Unable to copy from user.");
        goto failure;
      }
      if (driver_get_physoffset_alloc(alloc, info.virtaddr, &info.physoffset) != SUCCESS) {
        ERROR("Unable to get the physoffset for alloc %p", handle);
        goto failure;
      }
      if (copy_to_user(
            (msg_t*) arg,
            &info,
            sizeof(msg_t))) {
        ERROR("Unable to copy alloc physoffset for %p", handle);
        goto failure;
      }
      break;
    default:
      ERROR("The command is not valid!");
      goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int contalloc_mmap(struct file *file, struct vm_area_struct *vma)
{
  cont_alloc_t *alloc = find_alloc(file);
  if (alloc == NULL) {
    ERROR("Unable to find alloc for handle %p", file);
    return FAILURE;
  }
  return driver_mmap_alloc(alloc, vma);
}
