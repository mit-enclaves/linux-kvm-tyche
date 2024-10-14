//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "riscv64.h"
#include <linux/kernel.h>
#include "keystone.h"
#include <linux/dma-mapping.h>
#include <linux/mm.h>

#include "domains.h"

/* Destroy all memory associated with an EPM */
int epm_destroy(struct epm* epm) {

  if(!epm->ptr || !epm->size)
    return 0;

  /* free the EPM hold by the enclave */
  if (epm->is_cma) {
    dma_free_coherent(keystone_dev.this_device,
        epm->size,
        (void*) epm->ptr,
        epm->pa);
  } else {
    free_pages(epm->ptr, epm->order);
  }

  return 0;
}

/* Create an EPM and initialize the free list */
#if defined(TYCHE)
int epm_init(struct epm* epm, unsigned int min_pages, driver_domain_t* tyche_domain)
#else
int epm_init(struct epm* epm, unsigned int min_pages)
#endif
{
  vaddr_t epm_vaddr = 0;
  unsigned long order = 0;
  unsigned long count = min_pages;
  phys_addr_t device_phys_addr = 0;
  int ret;

  /* try to allocate contiguous memory */
  epm->is_cma = 0;
  order = ilog2(min_pages - 1) + 1;
  count = 0x1 << order;

// #if defined(TYCHE)

//   int alloc_result = driver_mmap_segment(tyche_domain, vma); 
//  //(NULL, (size_t) (slot->size), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, domain->handle, 0);

//   if (alloc_result) {
//     keystone_err("failed to allocate %lu page(s)\n", count);
//     return -ENOMEM;
//   }

//   segment_t* segment = dll_tail(&tyche_domain->raw_segments);
//   if (segment == NULL) {
//     keystone_err("failed to get domain segment\n");
//     return -ENOMEM;
//   }

//   epm_vaddr = segment->va;

//   keystone_err("KEYSTONE_DRIVER: The phys address %llx, virt: %llx", (usize) __pa(epm_vaddr), (usize) epm_vaddr);
// #else
  keystone_info("Alloca pages exact to allocate the pages for size %llx.", order);
  // epm_vaddr = alloc_pages_exact(order, GFP_KERNEL); 
  // if (epm_vaddr == NULL) {
  //   keystone_err("Alloca pages exact failed to allocate the pages for size %llx.", order);
  //   return -ENOMEM;
  // }
  //memset(epm_vaddr, 0, order);


  /* prevent kernel from complaining about an invalid argument */
  if (order <= MAX_ORDER)
    epm_vaddr = (vaddr_t) __get_free_pages(GFP_HIGHUSER, order);

#ifdef CONFIG_CMA
   /* If buddy allocator fails, we fall back to the CMA */
  if (!epm_vaddr) {
    epm->is_cma = 1;
    count = min_pages;

    keystone_info("Alloca pages exact to allocate the pages for count %llx.", count << PAGE_SHIFT);

    epm_vaddr = (vaddr_t) dma_alloc_coherent(keystone_dev.this_device,
      count << PAGE_SHIFT,
      &device_phys_addr,
      GFP_KERNEL | __GFP_DMA32);

    keystone_info("Alloca pages exact with epm_vaddr %llx.", epm_vaddr);

    if(!device_phys_addr)
      epm_vaddr = 0;
  }
#endif
// #endif

  if(!epm_vaddr) {
    keystone_err("failed to allocate %lu page(s)\n", count);
    return -ENOMEM;
  }

  /* zero out */
  memset((void*)epm_vaddr, 0, PAGE_SIZE*count);

  epm->root_page_table = (void*)epm_vaddr;
  epm->pa = __pa(epm_vaddr);
  epm->order = order;
  epm->size = count << PAGE_SHIFT;
  epm->ptr = epm_vaddr;

  // Create a corresponding segment in Tyche
  ret = driver_add_raw_segment(tyche_domain, epm_vaddr, epm->pa, PAGE_SIZE * count);
  if (ret) {
    keystone_err("Failled to add raw segment");
    return FAILURE;
  }

  return 0;
}

int utm_destroy(struct utm* utm){

  if(utm->ptr != NULL){
    free_pages((vaddr_t)utm->ptr, utm->order);
  }

  return 0;
}

int utm_init(struct utm* utm, size_t untrusted_size)
{
  unsigned long req_pages = 0;
  unsigned long order = 0;
  unsigned long count;
  req_pages += PAGE_UP(untrusted_size)/PAGE_SIZE;
  order = ilog2(req_pages - 1) + 1;
  count = 0x1 << order;

  utm->order = order;

  /* Currently, UTM does not utilize CMA.
   * It is always allocated from the buddy allocator */
  utm->ptr = (void*) __get_free_pages(GFP_HIGHUSER, order);
  if (!utm->ptr) {
    keystone_err("failed to allocate UTM (size = %ld bytes)\n",(1<<order));
    return -ENOMEM;
  }

  utm->size = count * PAGE_SIZE;
  if (utm->size != untrusted_size) {
    /* Instead of failing, we just warn that the user has to fix the parameter. */
    keystone_warn("shared buffer size is not multiple of PAGE_SIZE\n");
  }

  return 0;
}
