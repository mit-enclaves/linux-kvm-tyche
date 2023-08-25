#include <linux/ioctl.h>
#include <linux/kernel.h>   /* printk() */
#include <linux/cdev.h> 
#include <linux/device.h>
#include <linux/fs.h>

#include "common.h"
#include "domains.h"
#define _IN_MODULE
#include "tyche_driver.h"
#include "tyche_ioctl.h"
#undef _IN_MODULE
// —————————————————————— Global Driver Configuration ——————————————————————— //
static char* device_name = "tyche";
static char* device_class = "tyche";
static char* device_region = "tyche";

dev_t dev = 0;
static struct cdev tyche_cdev;
static struct class *dev_class;

// ———————————————————————————— File Operations ————————————————————————————— //

// File operation structure
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .open           = tyche_open,
        .release        = tyche_close,
        .unlocked_ioctl = tyche_ioctl,
        .mmap           = tyche_mmap,
};

// ———————————————————————————— Driver Functions ———————————————————————————— //


int tyche_register(void)
{
  // Allocating Major number
  if((alloc_chrdev_region(&dev, 0, 1, device_region)) <0){
    ERROR("cannot allocate major number\n");
    return FAILURE;
  }
  LOG("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

  // Creating the cdev structure
  cdev_init(&tyche_cdev, &fops);

  // Adding character device to the system.
  if ((cdev_add(&tyche_cdev, dev, 1)) < 0)
  {
    ERROR("Cannot add the device to the system.\n");
    goto r_class;
  }

  // Creating the struct class.
  if ((dev_class = class_create(device_class)) == NULL)
  {
    ERROR("Cannot create the struct class.\n");
    goto r_class;
  }

  // Creating the device.
  if ((device_create(dev_class, NULL, dev, NULL, device_name)) == NULL)
  {
    ERROR("Cannot create the Device 1\n");
    goto r_device;
  }

  driver_init_domains();
  LOG("Tyche driver registered!\n");
  trace_printk("Tyche driver initialized\n");
  return SUCCESS; 

r_device:
  class_destroy(dev_class);
r_class:
  unregister_chrdev_region(dev, 1);
  return FAILURE;
}

void tyche_unregister(void)
{
  device_destroy(dev_class, dev);
  class_destroy(dev_class);
  cdev_del(&tyche_cdev);
  unregister_chrdev_region(dev, 1);
  LOG("Tyche driver unregistered!\n");
}

// —————————————————————————————————— API ——————————————————————————————————— //

int tyche_open(struct inode* inode, struct file* file) 
{
  if (file == NULL) {
    ERROR("We received a Null file descriptor.");
    goto failure;
  }
  if (driver_create_domain(file, NULL) != SUCCESS) {
    ERROR("Unable to create a new domain");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_close(struct inode* inode, struct file* handle)
{
  driver_domain_t * dom = find_domain(handle);
   if (dom == NULL || driver_delete_domain(dom) != SUCCESS) {
        ERROR("Unable to delete the domain %p", handle);
        goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}


long tyche_ioctl(struct file* handle, unsigned int cmd, unsigned long arg)
{
  msg_info_t info = {UNINIT_USIZE, UNINIT_USIZE}; 
  msg_entry_on_core_t commit = {0, 0, 0, 0};
  msg_mprotect_t mprotect = {0, 0, 0, 0};
  msg_switch_t transition = {0};
  msg_set_perm_t perm = {0};
  driver_domain_t *domain = find_domain(handle);
  if (domain == NULL) {
    ERROR("Unable to find the domain %p!\n", handle);
    goto failure;
  }
  switch(cmd) {
    case TYCHE_GET_PHYSOFFSET:
      if (driver_get_physoffset_domain(domain, &info.physoffset) != SUCCESS) {
        ERROR("Unable to get the physoffset for domain %p", handle);
        goto failure;
      }
      if (copy_to_user(
            (msg_info_t*) arg, 
            &info, 
            sizeof(msg_info_t))) {
        ERROR("Unable to copy domain physoffset for %p", handle);
        goto failure;
      }
      break;
    case TYCHE_COMMIT:
      if (driver_commit_domain(domain) != SUCCESS) {
        ERROR("Commit failed for domain %p", handle);
        goto failure;
      }
      break;
    case TYCHE_SET_TRAPS:
        if (copy_from_user(
            &perm,
            (msg_set_perm_t*) arg,
            sizeof(msg_set_perm_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      if (driver_set_traps(domain, perm.value) != SUCCESS) {
        ERROR("Setting traps failed for domain %p", handle);
        goto failure;
      }
      break;
   case TYCHE_SET_CORES:
        if (copy_from_user(
            &perm,
            (msg_set_perm_t*) arg,
            sizeof(msg_set_perm_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      if (driver_set_cores(domain, perm.value) != SUCCESS) {
        ERROR("Setting cores failed for domain %p", handle);
        goto failure;
      }
      break;
   case TYCHE_SET_PERM:
        if (copy_from_user(
            &perm,
            (msg_set_perm_t*) arg,
            sizeof(msg_set_perm_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      if (driver_set_perm(domain, perm.value) != SUCCESS) {
        ERROR("Setting perm failed for domain %p", handle);
        goto failure;
      }
      break;
   case TYCHE_SET_SWITCH:
        if (copy_from_user(
            &perm,
            (msg_set_perm_t*) arg,
            sizeof(msg_set_perm_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      if (driver_set_switch(domain, perm.value) != SUCCESS) {
        ERROR("Setting perm failed for domain %p", handle);
        goto failure;
      }
      break;
   case TYCHE_SET_ENTRY_POINT:
        if (copy_from_user(
            &commit,
            (msg_entry_on_core_t*) arg,
            sizeof(msg_entry_on_core_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      if (driver_set_entry_on_core(
            domain,
            commit.core,
            commit.page_tables,
            commit.entry,
            commit.stack) != SUCCESS) {
        ERROR("Setting perm failed for domain %p", handle);
        goto failure;
      }
      break;
    case TYCHE_MPROTECT:
      if (copy_from_user(
            &mprotect,
            (msg_mprotect_t*) arg,
            sizeof(msg_mprotect_t))) {
        ERROR("Unable to copy arguments from user.");
        goto failure;
      }
      if (driver_mprotect_domain(
            domain,
            mprotect.start,
            mprotect.size,
            mprotect.flags,
            mprotect.tpe) != SUCCESS) {
        ERROR("Unable to mprotect he region for domain %p", handle);
        goto failure;
      }
      break;
    case TYCHE_TRANSITION:
      if (copy_from_user(
            &transition,
            (msg_switch_t*) arg,
            sizeof(msg_switch_t))) {
        ERROR("Unable to copy arguments from user.");
        goto failure;
      }
      if (driver_switch_domain(domain, transition.args) != SUCCESS) {
        ERROR("Unable to switch to domain %p", handle);
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

int tyche_mmap(struct file *file, struct vm_area_struct *vma)
{
  driver_domain_t *dom = find_domain(file);
  if (dom == NULL) {
    ERROR("Unable to find domain for handle %p", file);
    return FAILURE;
  }
  return driver_mmap_segment(dom, vma);
}
