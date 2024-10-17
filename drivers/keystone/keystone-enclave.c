//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <linux/dma-mapping.h>
#include "keystone.h"
#include "domains.h"
/* idr for enclave UID to struct enclave */
DEFINE_IDR(idr_enclave);
DEFINE_MUTEX(idr_enclave_lock);

#define ENCLAVE_IDR_MIN 0x1000
#define ENCLAVE_IDR_MAX 0xffff

unsigned long calculate_required_pages(
    unsigned long eapp_sz,
    unsigned long eapp_stack_sz,
    unsigned long rt_sz,
    unsigned long rt_stack_sz)
{
  unsigned long req_pages = 0;

  req_pages += PAGE_UP(eapp_sz)/PAGE_SIZE;
  req_pages += PAGE_UP(eapp_stack_sz)/PAGE_SIZE;
  req_pages += PAGE_UP(rt_sz)/PAGE_SIZE;
  req_pages += PAGE_UP(rt_stack_sz)/PAGE_SIZE;

  // FIXME: calculate the required number of pages for the page table.
  // For now, we must allocate at least 1 (top) + 2 (enclave) + 2 (runtime) pages for pg tables
  req_pages += 15;
  return req_pages;
}

/* Smart destroy, handles partial initialization of epm and utm etc */
int destroy_enclave(struct enclave* enclave)
{
  struct epm* epm;
  struct utm* utm;

  keystone_info("Destroy enclave");

  if (enclave == NULL)
    return -ENOSYS;

  epm = enclave->epm;
  utm = enclave->utm;

  if (epm)
  {
    epm_destroy(epm);
    kfree(epm);
  }
  if (utm)
  {
    utm_destroy(utm);
    kfree(utm);
  }
  kfree(enclave);
  return 0;
}

#if defined(TYCHE)
struct enclave* create_enclave(unsigned long min_pages, driver_domain_t* tyche_domain)
#else
struct enclave* create_enclave(unsigned long min_pages)
#endif
{
  struct enclave* enclave;
  unsigned long core;

  enclave = kmalloc(sizeof(struct enclave), GFP_KERNEL);
  if (!enclave){
    keystone_err("failed to allocate enclave struct\n");
    goto error_no_free;
  }

  enclave->eid = -1;
  enclave->utm = NULL;
  enclave->close_on_pexit = 1;

  enclave->epm = kmalloc(sizeof(struct epm), GFP_KERNEL);  
  //enclave->epm = alloc_pages_exact(sizeof(struct epm), GFP_KERNEL);
  enclave->is_init = true;
  if (!enclave->epm)
  {
    keystone_err("failed to allocate epm\n");
    goto error_destroy_enclave;
  }

#if defined(TYCHE)
  enclave->tyche_domain = tyche_domain;
  enclave->min_pages = min_pages;
  // With Tyche we do not allocate the EPM directly, we instead wait for the mmap
  if(epm_init(enclave->epm, min_pages, tyche_domain)) {
    keystone_err("failed to initialize epm\n");
    goto error_destroy_enclave;
  }


  // Grant permissions
  for (unsigned int p = TYCHE_CONFIG_R16; p < TYCHE_NR_CONFIGS; p++) {
    if (driver_set_domain_configuration(tyche_domain, p, ~((uint64_t) 0)) != SUCCESS) {
      keystone_err("Unable to set configuration %u", p);
      goto error_destroy_enclave;
    }
  }

  // Add core permissions
  if (driver_set_domain_configuration(tyche_domain, TYCHE_CONFIG_CORES, 0xFFFFFFFF)) {
    keystone_err("Failed to set allowed cores");
    goto error_destroy_enclave;
  }

  core = get_cpu();
  put_cpu();

  // Alloc context
  if (driver_alloc_core_context(tyche_domain, core)) {
    keystone_err("Failled to allocate core context on cpu %d", core);
    goto error_destroy_enclave;
  }

#else
  if(epm_init(enclave->epm, min_pages)) {
    keystone_err("failed to initialize epm\n");
    goto error_destroy_enclave;
  }
#endif

  return enclave;

 error_destroy_enclave:
  destroy_enclave(enclave);
 error_no_free:
  return NULL;
}

unsigned int enclave_idr_alloc(struct enclave* enclave)
{
  unsigned int ueid;

  mutex_lock(&idr_enclave_lock);
  ueid = idr_alloc(&idr_enclave, enclave, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
  mutex_unlock(&idr_enclave_lock);

  if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
    keystone_err("failed to allocate UID\n");
    return 0;
  }

  return ueid;
}

struct enclave* enclave_idr_remove(unsigned int ueid)
{
  struct enclave* enclave;
  mutex_lock(&idr_enclave_lock);
  enclave = idr_remove(&idr_enclave, ueid);
  mutex_unlock(&idr_enclave_lock);
  return enclave;
}

struct enclave* get_enclave_by_id(unsigned int ueid)
{
  struct enclave* enclave;
  mutex_lock(&idr_enclave_lock);
  enclave = idr_find(&idr_enclave, ueid);
  mutex_unlock(&idr_enclave_lock);
  return enclave;
}
