//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "keystone.h"
#include "keystone-sbi.h"
#include "keystone_user.h"
#include <asm/sbi.h>
#include <linux/uaccess.h>
#include "domains.h"

int __keystone_destroy_enclave(unsigned int ueid);

int keystone_create_enclave(struct file *filep, unsigned long arg)
{
  /* create parameters */
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  struct enclave *enclave;
  
#if defined(TYCHE)
  driver_domain_t* ptr;
  //Neelu TODO: Not sure if aliased should be 1 or not 
  //I'm following the KVM guideline atm 
  keystone_info("Creating domain\n");
  if (driver_create_domain(NULL, &ptr, 1) != SUCCESS) {
		keystone_err("Unable to create a domain VM.\n");
		return -ENOMEM;
	}
  enclave = create_enclave(enclp->min_pages, ptr);
#else 
  enclave = create_enclave(enclp->min_pages);
#endif 

  if (enclave == NULL) {
    return -ENOMEM;
  }

//#if !defined(TYCHE)
 // Neelu: I guess these aren't used anyway? Not sure...
  /* Pass base page table */
  enclp->pt_ptr = __pa(enclave->epm->root_page_table);
  enclp->epm_size = enclave->epm->size;
//#endif
  /* allocate UID */
  enclp->eid = enclave_idr_alloc(enclave);
  keystone_err("Done creating domain\n");
  filep->private_data = (void *) enclp->eid;
  keystone_err("Returning from keystone_create_enclave\n");
  return 0;
}


int keystone_finalize_enclave(unsigned long arg)
{
  struct sbiret ret;
  struct enclave *enclave;
  struct utm *utm;
  struct keystone_sbi_create_t create_args;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  unsigned long core = get_cpu();

  keystone_info("Keystone finalize enclave");

  enclave = get_enclave_by_id(enclp->eid);
  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  enclave->is_init = false;

  /* SBI Call */
  create_args.epm_region.paddr = enclave->epm->pa;
  create_args.epm_region.size = enclave->epm->size;

  utm = enclave->utm;

  if (utm) {
    create_args.utm_region.paddr = __pa(utm->ptr);
    create_args.utm_region.size = utm->size;
  } else {
    create_args.utm_region.paddr = 0;
    create_args.utm_region.size = 0;
  }

  // physical addresses for runtime, user, and freemem
  create_args.runtime_paddr = enclp->runtime_paddr;
  create_args.user_paddr = enclp->user_paddr;
  create_args.free_paddr = enclp->free_paddr;

  create_args.params = enclp->params;


  // First we prepare the memory
  if (driver_mprotect_domain(
    enclave->tyche_domain,
    enclave->epm->ptr,
    enclave->epm->size,
    MEM_READ | MEM_WRITE | MEM_EXEC,
    SHARED, // TODO: set as confidential later
    1)) {
    keystone_err("Failed to mprotect domain");
    ret.error = -1;
    goto error_destroy_enclave;
  }

  // And then we commit the domain
  if (driver_commit_domain(enclave->tyche_domain, 1)) {
    keystone_err("Failed to commit domain");
    ret.error = -1;
    goto error_destroy_enclave;
  }
  ret.error = 0;
  ret.value = 0;

  /* ret = sbi_sm_create_enclave(&create_args); */

  /* if (ret.error) { */
  /*   keystone_err("keystone_create_enclave: SBI call failed with error codd %ld\n", ret.error); */
  /*   goto error_destroy_enclave; */
  /* } */

  // Configure enclave initial registers
  if (driver_set_domain_core_config(enclave->tyche_domain, core, GUEST_RIP, create_args.params.runtime_entry)) {
    keystone_err("Failled to set mepc on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, SEPC, create_args.params.user_entry)) {
    keystone_err("Failed to set sepc on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, MSTATUS, 1 << 11)) {
    keystone_err("Failed to set SEPC on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, GUEST_CR3, create_args.epm_region.paddr)) {
    keystone_err("Failled to set satp on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, EXCEPTION_BITMAP, 0x0 /*0xffffff5d*/ /*0xffffffff*/)) { // Do not delegated access/store faults
    keystone_err("Failled to set medeleg on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A1, create_args.epm_region.paddr)) {
    keystone_err("Failed to set a1 on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A2, create_args.epm_region.size)) {
    keystone_err("Failed to set a2 on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A3, create_args.runtime_paddr)) {
    keystone_err("Failed to set a3 on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A4, create_args.user_paddr)) {
    keystone_err("Failed to set a4 on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A5, create_args.free_paddr)) {
    keystone_err("Failed to set a5 on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A6, create_args.utm_region.paddr)) {
    keystone_err("Failed to set a6 on cpu %lu", core);
    goto error_destroy_enclave;
  }
  if (driver_set_domain_core_config(enclave->tyche_domain, core, REG_GP_A7, create_args.utm_region.size)) {
    keystone_err("Failed to set a7 on cpu %lu", core);
    goto error_destroy_enclave;
  }

  put_cpu();

  // TODO: How should we gat an Enclave ID? Do we even need it?
  enclave->eid = ret.value;

  return 0;

error_destroy_enclave:
  /* This can handle partial initialization failure */
  put_cpu();
  destroy_enclave(enclave);

  return -EINVAL;

}

int keystone_run_enclave(unsigned long data)
{
  /* struct sbiret ret; */
  unsigned long ueid;
  struct enclave* enclave;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;
  unsigned long core = get_cpu();
  usize result;

  /* keystone_info("Keystone run enclave"); */

  ueid = arg->eid;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid < 0) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  /* ret = sbi_sm_run_enclave(enclave->eid); */

  /* arg->error = ret.error; */
  /* arg->value = ret.value; */

  /* keystone_info("Switching domain!"); */
  if (driver_switch_domain(enclave->tyche_domain, core)) {
    keystone_err("Failed to switch domain");
    arg->error = -1;
    // TODO: pass return value :)
  }
  if (driver_get_domain_core_config(enclave->tyche_domain, core, REG_GP_A1, &result)) {
    keystone_err("Failed to read a1 after returning from domain");
  }
  arg->error = 0;
  switch (result) {
    case 0:
        /* keystone_info("Exited due to interrupt"); */
        arg->value = 0;
        arg->error = 100002;
        break;
    case 1:
        keystone_info("Exited due to edge call");
        arg->value = 0;
        arg->error = 100011;
        break;
    case 2:
        keystone_info("Exited due to enclave exit");
        arg->value = result;
        arg->error = 0;
        break;
    default:
        keystone_warn("Invalid return code: %lu", result);
        arg->value = 0;
  }
  /* keystone_info("Returned from enclave: value %lu, errror %lu", arg->value, arg->error); */

  put_cpu();

  return 0;
}

int utm_init_ioctl(struct file *filp, unsigned long arg)
{
  int ret = 0;
  struct utm *utm;
  struct enclave *enclave;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  long long unsigned untrusted_size = enclp->params.untrusted_size;

  keystone_info("Keystone UTM init");

  enclave = get_enclave_by_id(enclp->eid);

  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  utm = kmalloc(sizeof(struct utm), GFP_KERNEL);
  if (!utm) {
    ret = -ENOMEM;
    return ret;
  }

  ret = utm_init(utm, untrusted_size);

  /* prepare for mmap */
  enclave->utm = utm;

  enclp->utm_free_ptr = __pa(utm->ptr);

  return ret;
}


int keystone_destroy_enclave(struct file *filep, unsigned long arg)
{
  int ret;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  unsigned long ueid = enclp->eid;

  keystone_info("Keystone destroy enclave");

  ret = __keystone_destroy_enclave(ueid);
  if (!ret) {
    filep->private_data = NULL;
  }
  return ret;
}

int __keystone_destroy_enclave(unsigned int ueid)
{
  struct enclave *enclave;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid >= 0) {
    if (driver_delete_domain(enclave->tyche_domain)) {
      keystone_err("fatal: cannot destroy enclave");
      return -EINVAL;
    }
  } else {
    keystone_warn("keystone_destroy_enclave: skipping (enclave does not exist)\n");
  }


  destroy_enclave(enclave);
  enclave_idr_remove(ueid);

  return 0;
}

int keystone_resume_enclave(unsigned long data)
{
  struct sbiret ret;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;
  unsigned long ueid = arg->eid;
  struct enclave* enclave;
  enclave = get_enclave_by_id(ueid);

  keystone_info("Keystone resume enclave");

  if (!enclave)
  {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid < 0) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_resume_enclave(enclave->eid);

  arg->error = ret.error;
  arg->value = ret.value;

  return 0;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  char data[512];

  size_t ioc_size;

  if (!arg)
    return -EINVAL;

  ioc_size = _IOC_SIZE(cmd);
  ioc_size = ioc_size > sizeof(data) ? sizeof(data) : ioc_size;

  if (copy_from_user(data,(void __user *) arg, ioc_size))
    return -EFAULT;

  switch (cmd) {
    case KEYSTONE_IOC_CREATE_ENCLAVE:
      ret = keystone_create_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_FINALIZE_ENCLAVE:
      ret = keystone_finalize_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_DESTROY_ENCLAVE:
      ret = keystone_destroy_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_RUN_ENCLAVE:
      ret = keystone_run_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_RESUME_ENCLAVE:
      ret = keystone_run_enclave((unsigned long) data);
      /* ret = keystone_resume_enclave((unsigned long) data); */
      break;
    /* Note that following commands could have been implemented as a part of ADD_PAGE ioctl.
     * However, there was a weird bug in compiler that generates a wrong control flow
     * that ends up with an illegal instruction if we combine switch-case and if statements.
     * We didn't identified the exact problem, so we'll have these until we figure out */
    case KEYSTONE_IOC_UTM_INIT:
      ret = utm_init_ioctl(filep, (unsigned long) data);
      break;
    default:
      keystone_err("Invalid ioctl");
      return -ENOSYS;
  }

  if (copy_to_user((void __user*) arg, data, ioc_size))
    return -EFAULT;

  return ret;
}

int keystone_release(struct inode *inode, struct file *file) {
  unsigned long ueid = (unsigned long)(file->private_data);
  struct enclave *enclave;

  keystone_info("Keystone release");

  /* enclave has been already destroyed */
  if (!ueid) {
    return 0;
  }

  /* We need to send destroy enclave just the eid to close. */
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    /* If eid is set to the invalid id, then we do not do anything. */
    return -EINVAL;
  }
  if (enclave->close_on_pexit) {
    return __keystone_destroy_enclave(ueid);
  }
  return 0;
}
