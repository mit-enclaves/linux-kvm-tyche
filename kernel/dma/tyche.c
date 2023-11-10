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

int tyche_create_domain(bool io, int *management)
{
	vmcall_frame_t frame = {
		.vmcall = 1,
		.arg_1 = io,
	};

	if (tyche_call(&frame)) {
		pr_warn("tyche create_domain hypercall failed");
		return 1;
	}
	*management = frame.value_1;

	return 0;
}

int tyche_send(unsigned long long capa, unsigned long long to)
{
	vmcall_frame_t frame = {
		.vmcall = 4,
		.arg_1 = capa,
		.arg_2 = to,
	};

	if (tyche_call(&frame)) {
		pr_warn("tyche send hypercall failed");
		return 1;
	}

	if (frame.value_1 != capa) {
		pr_warn("revocation handle is not the original one");
		return 1;
	}

	return 0;
}

int tyche_segment_region(unsigned long long capa, unsigned long long *left,
			 unsigned long long *right, unsigned long start1,
			 unsigned long end1, unsigned long prot1,
			 unsigned long start2, unsigned long end2,
			 unsigned long prot2)
{
	vmcall_frame_t frame = {
		.vmcall = 5,
		.arg_1 = capa,
		.arg_2 = start1,
		.arg_3 = end1,
		.arg_4 = start2,
		.arg_5 = end2,
		.arg_6 = (prot1 << 32 | prot2),
	};

	if (tyche_call(&frame)) {
		pr_warn("tyche segment_region hypercall failed");
		return 1;
	}

	*left = frame.value_1;
	*right = frame.value_2;
	return 0;
}

int tyche_enum(unsigned long *next, unsigned long *start, unsigned long *size,
	       unsigned long *prot)
{
	uint8_t capa_type = 0;
	uint8_t flags = 0;
	bool active = 0;
	bool confidential = 0;

	pr_info("%s: next=%lu", __func__, *next);
	vmcall_frame_t frame = {
		.vmcall = 8,
		.arg_1 = *next,
	};

	if (tyche_call(&frame)) {
		pr_warn("tyche enumerate hypercall failed");
		return 1;
	}

	pr_info("enum returns: start=0x%llx, end=0x%llx, cap_type=0x%llx, alias=0x%llx, next=0x%llx",
		frame.value_1, frame.value_2, frame.value_3, frame.value_4,
		frame.value_5);

	capa_type = frame.value_3 & 0xff;
	flags = frame.value_3 >> 8;
	active = flags & 0b01;
	confidential = flags & 0b10;
	*next = frame.value_5;

	// Check if the cap returned is a region
	if (capa_type != 0) {
		pr_info("cap is not region");
		return 1;
	}

	// Check if the region is active
	if (!active) {
		pr_info("region is not active");
		return 1;
	}

	// Check if the region is shared
	if (confidential) {
		pr_info("region is not shared");
		return 1;
	}

	// Check if the region is aliased
	if (frame.value_4 != 0) {
		pr_info("shared region is aliased: 0x%llx -> 0x%llx",
			frame.value_1, frame.value_4);
		*start = frame.value_4;
	} else {
		*start = frame.value_1;
	}

	*size = frame.value_2 - frame.value_1 + 1;
	*prot = frame.value_3;

	return 0;
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

int __init tyche_find_shared_region(unsigned long *capa_index,
				    unsigned long *start, unsigned long *len,
				    unsigned long *prot)
{
	unsigned long next = 0;
	unsigned long begin = 0;
	unsigned long size = 0;
	unsigned long flags = 0;

	do {
		*capa_index = next;
		if (tyche_enum(&next, &begin, &size, &flags) == 0) {
			pr_info("start=0x%lx, size=%ld, prot=%lx", start, size,
				flags);
			*start = begin;
			*len = size;
			*prot = flags;
			return 0;
		}
	} while (next != 0);

	return 1;
}
