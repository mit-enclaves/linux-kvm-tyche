#include "linux/rwsem.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include "tyche_api.h"
#include <linux/ioctl.h>
#include <linux/kernel.h>   /* printk() */
#include <linux/cdev.h> 
#include <linux/device.h>
#include <linux/fs.h>

#include "common.h"
#include "common_log.h"
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
  if ((dev_class = class_create(THIS_MODULE, device_class)) == NULL)
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
  if (driver_create_domain(file, NULL, 0) != SUCCESS) {
    ERROR("Unable to create a new domain");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_close(struct inode* inode, struct file* handle)
{
  driver_domain_t * dom = find_domain(handle, true);
   if (dom == NULL || driver_delete_domain(dom) != SUCCESS) {
        ERROR("Unable to delete the domain %p", handle);
        goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}

#define ACQUIRE_DOM(write) \
    domain = find_domain(handle, write); \
    if (domain == NULL) { \
      ERROR("Unable to find domain %p", handle); \
      goto failure; \
    }

#define RELEASE_DOM(write) \
  if (write) { \
    up_write(&(domain->rwlock)); \
  } else { \
    up_read(&(domain->rwlock)); \
  }


long tyche_ioctl(struct file* handle, unsigned int cmd, unsigned long arg)
{
  msg_info_t info = {UNINIT_USIZE, UNINIT_USIZE}; 
  msg_mprotect_t mprotect = {0, 0, 0, 0};
  msg_set_perm_t perm = {0};
  driver_domain_t *domain = NULL;
  msg_create_pipe_t pipe = {0};
  attest_buffer_t attest_buff = {0, 0, 0};
  char *buff;
  switch(cmd) {
    case TYCHE_GET_PHYSOFFSET:
      if (copy_from_user(
            &info,
            (msg_info_t*) arg,
            sizeof(msg_info_t))) {
        ERROR("Unable to copy info arguments from user.");
        goto failure;
      }
      ACQUIRE_DOM(false);
      if (driver_get_physoffset_domain(domain, info.virtaddr, &info.physoffset) != SUCCESS) {
        ERROR("Unable to get the physoffset for domain %p", handle);
        RELEASE_DOM(false);
        goto failure;
      }
      if (copy_to_user(
            (msg_info_t*) arg, 
            &info, 
            sizeof(msg_info_t))) {
        ERROR("Unable to copy domain physoffset for %p", handle);
        RELEASE_DOM(false);
        goto failure;
      }
      RELEASE_DOM(false);
      break;
    case TYCHE_COMMIT:
      ACQUIRE_DOM(true);
      if (driver_commit_domain(domain, 1) != SUCCESS) {
        ERROR("Commit failed for domain %p", handle);
        RELEASE_DOM(true);
        goto failure;
      }
      RELEASE_DOM(true);
      break;
    case TYCHE_SET_DOMAIN_CONFIGURATION:
      if (copy_from_user(
            &perm,
            (msg_set_perm_t*) arg,
            sizeof(msg_set_perm_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      if (perm.idx < TYCHE_CONFIG_PERMISSIONS || perm.idx >= TYCHE_NR_CONFIGS) {
        ERROR("Invalid configuration value.");
        goto failure;
      }

      ACQUIRE_DOM(true);
      if (driver_set_domain_configuration(domain, perm.idx, perm.value) != SUCCESS) {
        ERROR("Setting traps failed for domain %p", handle);
        RELEASE_DOM(true);
        goto failure;
      }
      RELEASE_DOM(true);
      break;
    case TYCHE_SET_DOMAIN_CORE_CONFIG:
      if (copy_from_user(
            &perm,
            (msg_set_perm_t*) arg,
            sizeof(msg_set_perm_t))) {
        ERROR("Unable to copy perm arguments from user.");
        goto failure;
      }
      ACQUIRE_DOM(false);
      if (driver_set_domain_core_config(domain, perm.core, perm.idx, perm.value) != SUCCESS) {
        ERROR("Setting traps failed for domain %p", handle);
        RELEASE_DOM(false);
        goto failure;
      }
      RELEASE_DOM(false);
      break;
    case TYCHE_ALLOC_CONTEXT:
      usize core = (usize) arg;
      ACQUIRE_DOM(true);
      if (driver_alloc_core_context(domain, core) != SUCCESS) {
        ERROR("Unable to allocate core context!");
        RELEASE_DOM(true);
        goto failure;
      }
      RELEASE_DOM(true);
      break;
    case TYCHE_MPROTECT:
      if (copy_from_user(
            &mprotect,
            (msg_mprotect_t*) arg,
            sizeof(msg_mprotect_t))) {
        ERROR("Unable to copy arguments from user.");
        goto failure;
      }
      ACQUIRE_DOM(true);
      if (driver_mprotect_domain(
            domain,
            mprotect.start,
            mprotect.size,
            mprotect.flags,
            mprotect.tpe,
            NO_ALIAS) != SUCCESS) {
        ERROR("Unable to mprotect he region for domain %p", handle);
        RELEASE_DOM(true);
        goto failure;
      }
      RELEASE_DOM(true);
      break;
    case TYCHE_TRANSITION:
      ACQUIRE_DOM(false);
      if (driver_switch_domain(domain, arg) != SUCCESS) {
        ERROR("Unable to switch to domain %p", handle);
        RELEASE_DOM(false);
        goto failure;
      }
      RELEASE_DOM(false);
      break;
    case TYCHE_CREATE_PIPE:
      if (copy_from_user(&pipe, (msg_create_pipe_t*) arg,
            sizeof(msg_create_pipe_t))) {
        ERROR("Unable to copy the create pipe message");
        goto failure;
      }
      if (driver_create_pipe(&(pipe.id), pipe.phys_addr, pipe.size, pipe.flags,
            pipe.width) != SUCCESS) {
        ERROR("Failed to create a pipe.");
        goto failure;
      }
      if (copy_to_user((msg_create_pipe_t*) arg, &pipe,
            sizeof(msg_create_pipe_t))) {
        ERROR("Unable to copy result from create pipe.");
        goto failure;
      }
      break;
    case TYCHE_ACQUIRE_PIPE:
      ACQUIRE_DOM(true);
      if (driver_acquire_pipe(domain, (usize)arg) != SUCCESS) {\
        ERROR("Unable to acquire pipe");
        goto failure;
      }
      RELEASE_DOM(true);
      break;
    case TYCHE_GET_ATTESTATION:
      if (copy_from_user(&attest_buff, (attest_buffer_t *) arg,
            sizeof(attest_buffer_t))) {
        ERROR("Unable to copy the create pipe message");
        goto failure;
      }
      if (attest_buff.size > 4096) {
        // Limit the maximum capacity, to avoid user process forcing a OOM
        attest_buff.size = 4096;
      }
      buff = kmalloc(attest_buff.size, GFP_KERNEL);
      if (buff == NULL) {
        ERROR("Failed to allocate buffer in kernel");
        goto failure;
      }
      if (driver_serialize_attestation(buff,
                  attest_buff.size,
                  &attest_buff.written) != SUCCESS) {
        ERROR("Unable te serialize the attestation");
        goto failure;
      }
      if (copy_to_user((char *)attest_buff.start,
                  buff, attest_buff.written)) {
        ERROR("Unable to copy attestation buffer");
        goto failure;
      }
      if (copy_to_user((attest_buffer_t*) arg,
                  &attest_buff, sizeof(attest_buffer_t))) {
        ERROR("Unable to copy attestation results");
        goto failure;
      }
      break;
    default:
      ERROR("The command is not valid! %d", cmd);
      goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_mmap(struct file *file, struct vm_area_struct *vma)
{
  int res = FAILURE;
  driver_domain_t *dom = find_domain(file, true);
  if (dom == NULL) {
    ERROR("Unable to find domain for handle %p", file);
    return FAILURE;
  }
  res = driver_mmap_segment(dom, vma);
  // Unlock the domain.
  up_write(&(dom->rwlock));
  return res;
}
