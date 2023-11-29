#ifndef _LINUX_DMA_TYCHE_H
#define _LINUX_DMA_TYCHE_H

#include <linux/ctype.h>
#include <linux/swiotlb.h>

extern unsigned long shared_region_capa;
extern unsigned long swiotlb_region_capa;
extern int io_domain;
extern unsigned long shared_region;
extern unsigned long shared_region_sz;
extern unsigned long shared_region_prot;

struct tyche_region {
	size_t capa_index;
	size_t start;
	size_t end;
	size_t alias;
	bool active;
	bool confidential;
	uint8_t ops;
};

struct tyche_region_node {
	struct tyche_region region;
	struct list_head node;
};

#ifdef CONFIG_TYCHE_GUEST
#define TYCHE_SHARED_REGIONS 10
extern struct tyche_region tyche_shared_regions[TYCHE_SHARED_REGIONS];
extern size_t tyche_shared_region_len;
#endif

typedef unsigned long long capa_index_t;
typedef unsigned long long usize;

extern int tyche_create_domain(bool io, capa_index_t *management);

extern int tyche_send(capa_index_t dest, capa_index_t capa);
extern int tyche_segment_region(capa_index_t capa, capa_index_t *left,
				capa_index_t *right, usize start1, usize end1,
				usize prot1, usize start2, usize end2,
				usize prot2);
void *tyche_memblock_alloc(unsigned long start, unsigned long size);
int tyche_filter_capabilities(bool (*f)(struct tyche_region *),
			      void (*append)(struct tyche_region *,
					     struct dma_mem *),
			      struct dma_mem *mem);
#endif
