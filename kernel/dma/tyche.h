#ifndef _LINUX_DMA_TYCHE_H
#define _LINUX_DMA_TYCHE_H

#include <linux/ctype.h>

extern unsigned long shared_region_capa;
extern unsigned long swiotlb_region_capa;
extern int io_domain;
extern unsigned long shared_region;
extern unsigned long shared_region_sz;
extern unsigned long shared_region_prot;

int tyche_create_domain(bool io, int *management);
int tyche_send(unsigned long long capa, unsigned long long to);
int tyche_segment_region(unsigned long long capa, unsigned long long *left,
			 unsigned long long *right, unsigned long start1,
			 unsigned long end1, unsigned long prot1,
			 unsigned long start2, unsigned long end2,
			 unsigned long prot2);
int tyche_enum(unsigned long *next, unsigned long *start, unsigned long *size,
	       unsigned long *prot);
void *tyche_memblock_alloc(unsigned long start, unsigned long size);
int tyche_find_shared_region(unsigned long *capa_index, unsigned long *start,
			     unsigned long *len, unsigned long *prot);

#endif
