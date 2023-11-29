#include "tyche.h"
#include <linux/ctype.h>
#include <linux/printk.h>
#include <linux/memblock.h>

typedef struct vmcall_frame_t {
	// Vmcall id.
	uint64_t vmcall;

	// Arguments.
	uint64_t arg_1;
	uint64_t arg_2;
	uint64_t arg_3;
	uint64_t arg_4;
	uint64_t arg_5;
	uint64_t arg_6;

	// Results.
	uint64_t value_1;
	uint64_t value_2;
	uint64_t value_3;
	uint64_t value_4;
	uint64_t value_5;
	uint64_t value_6;
} vmcall_frame_t;

extern int tyche_call(vmcall_frame_t *frame);

static int serialize_tyche_region(size_t *capa_index, vmcall_frame_t *frame,
				  struct tyche_region *r)
{
	BUG_ON(!frame);
	BUG_ON(!r);

	uint8_t flags = frame->value_3 >> 8;

	r->capa_index = *capa_index;
	r->start = frame->value_1;
	r->end = frame->value_2;
	r->alias = frame->value_4;
	r->ops = flags >> 2;
	r->active = flags & 0b01;
	r->confidential = flags & 0b10;

	return 0;
}

static int tyche_enum(vmcall_frame_t *frame)
{
	BUG_ON(!frame);

	if (tyche_call(frame)) {
		pr_warn("tyche enumerate hypercall failed");
		return 1;
	}

	return 0;
}

// next points to zero if we have iterated all capas on the domain
// returns 1 if the current capa is not a region
// only inspect the region when the function returns 0 and next
static int tyche_enum_region(size_t *capa_index, struct tyche_region *r)
{
	vmcall_frame_t frame = {
		.vmcall = 8,
		.arg_1 = *capa_index,
	};

	if (tyche_enum(&frame)) {
		return 1;
	}

	if ((frame.value_3 & 0xff) != 0) {
		pr_info("cap is not region");
		*capa_index = frame.value_5;
		return 1;
	}

	serialize_tyche_region(capa_index, &frame, r);
	*capa_index = frame.value_5;

	return 0;
}

int tyche_filter_capabilities(bool (*f)(struct tyche_region *),
			      void (*append)(struct tyche_region *,
					     struct dma_mem *),
			      struct dma_mem *mem)
{
	struct tyche_region r;
	size_t capa_index = 0;
	size_t property = 0;

	do {
		if (tyche_enum_region(&capa_index, &r)) {
			continue;
		}

		pr_info("tyche_region: capa_index=%u, start=0x%lx, end=0x%lx, alias=0x%lx, active=%d, confidential=%d, ops=%u",
			r.capa_index, r.start, r.end, r.alias, r.active,
			r.confidential, r.ops);

		if (f(&r)) {
			append(&r, mem);
			property += 1;
		}
	} while (capa_index != 0);

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
