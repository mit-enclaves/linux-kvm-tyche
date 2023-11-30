#ifndef _LINUX_DMA_TYCHE_H
#define _LINUX_DMA_TYCHE_H

#include <linux/ctype.h>
#include <linux/swiotlb.h>
#include <tyche_capabilities_types.h>

typedef unsigned long long capa_index_t;
typedef unsigned long long usize;

extern int tyche_create_domain(bool io, capa_index_t *management);

extern int tyche_send(capa_index_t dest, capa_index_t capa);
extern int tyche_segment_region(capa_index_t capa, capa_index_t *left,
				capa_index_t *right, usize start1, usize end1,
				usize prot1, usize start2, usize end2,
				usize prot2);
void *tyche_memblock_alloc(unsigned long start, unsigned long size);
int tyche_filter_capabilities(bool (*f)(struct capability_t *),
			      void (*append)(struct capability_t *,
					     struct dma_mem *),
			      struct dma_mem *mem);
#endif
