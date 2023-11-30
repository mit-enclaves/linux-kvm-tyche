#include "tyche.h"
#include <linux/ctype.h>
#include <linux/printk.h>
#include <linux/memblock.h>
#include "ecs.h"

typedef struct vmcall_frame_t vmcall_frame_t;
extern int tyche_call(vmcall_frame_t *frame);

// next points to zero if we have iterated all capas on the domain
// returns 1 if the current capa is not a region
// only inspect the region when the function returns 0 and next
static int tyche_enum_capa(size_t *capa_index, capability_t *capa)
{
	capa_index_t next;

	if (enumerate_capa(*capa_index, &next, capa) != SUCCESS) {
		return FAILURE;
	}

	if (next != *capa_index + 1) {
		return FAILURE;
	}
	*capa_index = next;

	return SUCCESS;
}

int tyche_filter_capabilities(bool (*f)(capability_t *),
			      void (*append)(capability_t *, struct dma_mem *),
			      struct dma_mem *mem)
{
	capability_t cap;
	size_t capa_index = 0;
	size_t property = 0;

	pr_info("%s: %d", __func__, __LINE__);

	for (;;) {
		if (tyche_enum_capa(&capa_index, &cap) != SUCCESS) {
			break;
		}

		pr_info("tyche capa: capa_type=%d, capa_index=%u, start=0x%lx, end=0x%lx, flags=%x",
			cap.capa_type, cap.local_id, cap.info.region.start,
			cap.info.region.end, cap.info.region.flags);

		if (f(&cap)) {
			pr_info("append cap to mem");
			append(&cap, mem);
			property += 1;
		}
	}

	return property == 0;
}

void __init *tyche_memblock_alloc(unsigned long start, unsigned long size)
{
	void *tlb = NULL;

	if (!size) {
		pr_warn("Tyche: cannot allocate a swiotlb for size 0");
		return NULL;
	}

	pr_warn("allocating a swiotlb buffer on start=0x%llx, size=%lu", start,
		size);

	// Call the memblock functions to allocate this range for DMA
	tlb = memblock_alloc_try_nid(size, PAGE_SIZE, start, start + size,
				     NUMA_NO_NODE);

	if (!tlb) {
		pr_warn("%s: Failed to allocate %zu bytes tlb structure\n",
			__func__, size);
		return NULL;
	}

	return tlb;
}
