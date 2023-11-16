#ifndef _LINUX_DMA_TYCHE_H
#define _LINUX_DMA_TYCHE_H

#include <linux/ctype.h>

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
// extern list_head tyche_shared_regions;
#define TYCHE_SHARED_REGIONS 10
extern struct tyche_region tyche_shared_regions[TYCHE_SHARED_REGIONS];
extern size_t tyche_shared_region_len;
#endif

int tyche_create_domain(bool io, int *management);
int tyche_send(unsigned long long capa, unsigned long long to);
int tyche_segment_region(unsigned long long capa, unsigned long long *left,
			 unsigned long long *right, unsigned long start1,
			 unsigned long end1, unsigned long prot1,
			 unsigned long start2, unsigned long end2,
			 unsigned long prot2);
void *tyche_memblock_alloc(unsigned long start, unsigned long size);
int tyche_find_shared_regions(void);

#endif
