// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Luca Wilke <luw8000@gmail.com>
 *
 * This implements an abstraction for accessing the invalidation queue
 * that enables to use a para virtualized interface
 *
 */
#include "common_log.h"
#include "linux/spinlock_types_raw.h"
#include "iommu.h"
#include "tyche_api.h"

#ifdef NO_TYCHE
struct q_inval {
	raw_spinlock_t  q_lock;
	void		*desc;          /* invalidation queue */
	int             *desc_status;   /* desc status */
	int             free_head;      /* first free entry */
	int             free_tail;      /* last free entry */
	int             free_cnt;
	int descriptor_bytes; /*size of descriptor in bytes*/
};

int qinval_initialize(q_inval* self, struct intel_iommu* iommu) {
	struct page* desc_page;
    /*
	 * Need two pages to accommodate 256 descriptors of 256 bits each
	 * if the remapping hardware supports scalable mode translation.
	 */
	desc_page = alloc_pages_node(iommu->node, GFP_ATOMIC | __GFP_ZERO,
				     !!ecap_smts(iommu->ecap));
	if (!desc_page) {
		return -ENOMEM;
	}

	self->desc = page_address(desc_page);

	self->desc_status = kcalloc(QI_LENGTH, sizeof(int), GFP_ATOMIC);
	if (!self->desc_status) {
		free_page((unsigned long) self->desc);
		return -ENOMEM;
	}
	self->descriptor_bytes = 1 << qi_shift(iommu);

	raw_spin_lock_init(&self->q_lock);
    return 0;
}

size_t qinval_get_struct_bytes(void) {
	return sizeof(q_inval);
}

void qinval_enable_qi(q_inval *self, struct intel_iommu* iommu) {
	u64 val = virt_to_phys(self->desc);
	/*
	 * Set DW=1 and QS=1 in IQA_REG when Scalable Mode capability
	 * is present.
	 */
	if (ecap_smts(iommu->ecap))
		val |= (1 << 11) | 1;

	dmar_writeq(iommu->reg + DMAR_IQA_REG, val);

}

void qinval_free_inner(q_inval* self) {
    free_page((unsigned long)self->desc);
	kfree(self->desc_status);

}

struct qi_desc qinval_read_desc(struct q_inval* self, unsigned int offset) {
    struct qi_desc res;
	//the struct can fit the max descritpr size, but we might use smaller ones
    memcpy(&res, self->desc + offset, self->descriptor_bytes);
    return res;
}

void qinval_write_desc(struct q_inval* self, int offset, struct qi_desc* desc) {
    memcpy(self->desc+offset, desc, self->descriptor_bytes);
}

#else
struct q_inval {
	raw_spinlock_t  q_lock;
	int             *desc_status;   /* desc status */
	int             free_head;      /* first free entry */
	int             free_tail;      /* last free entry */
	int             free_cnt;
	int descriptor_bytes; /*size of descriptor in bytes*/
	size_t queue_order;

};

int qinval_initialize(q_inval* self, struct intel_iommu *iommu) {

	//1 << qi_shift(iommu) to compute descriptor with (either 128 or 256)
	self->desc_status = kcalloc(QI_LENGTH, sizeof(int), GFP_ATOMIC);
	if (!self->desc_status) {
		return -ENOMEM;
	}
	self->descriptor_bytes = 1 << qi_shift(iommu);

	raw_spin_lock_init(&self->q_lock);
    return 0;
}

size_t qinval_get_struct_bytes(void) {
	return sizeof(q_inval);
}

void qinval_enable_qi(q_inval* self, struct intel_iommu* iommu) {
   /* Using this interface, tyche never exposes control over the buffer for the invalidation queue
	* to the PV driver, as writes to the corresponding register will be blocked.
	* Thus, only our dedicated interface can be used to enqueue descriptors.
	* This allows us to securely do the GPA<->HPA swap for the writeback addrs
	*/
	tyche_pv_iommu_arg_builder_t in_builder;
	int res;


	tyche_pv_iommu_arg_builder_init(&in_builder);
	tyche_pv_iommu_arg_builder_append_u32(&in_builder, self->descriptor_bytes);
	res = tyche_pv_iommu(TYCHE_PV_IOMMU_QI_INIT, &(in_builder.buf), NULL);
	if(res) {
		BUG();
	}

}

void qinval_free_inner(q_inval *self) {
	kfree(self->desc_status);
}

struct qi_desc qinval_read_desc(struct q_inval* self, int32_t offset) {
   tyche_pv_iommu_arg_builder_t in_builder;
   tyche_pv_iommu_in_out_buf_u out;
   struct qi_desc desc;
	int res;

	tyche_pv_iommu_arg_builder_init(&in_builder);
	tyche_pv_iommu_arg_builder_append_u32(&in_builder, offset);
	res = tyche_pv_iommu(TYCHE_PV_IOMMU_QI_DESC_READ, &(in_builder.buf),&out);
	if(res) {
		BUG();
	}
	memcpy(&desc, out.as_bytes, self->descriptor_bytes);

	return desc;
}

void qinval_write_desc(struct q_inval* self, int32_t offset, struct qi_desc* value) {
	tyche_pv_iommu_arg_builder_t in_builder;
	int res;

	tyche_pv_iommu_arg_builder_init(&in_builder);
	tyche_pv_iommu_arg_builder_append_u8(&in_builder, self->descriptor_bytes);
	tyche_pv_iommu_arg_builder_append_int32(&in_builder, offset);
	tyche_pv_iommu_arg_builder_append_u64(&in_builder, value->qw0);
	tyche_pv_iommu_arg_builder_append_u64(&in_builder, value->qw1);
	if( self->descriptor_bytes == (256/8)) {
		tyche_pv_iommu_arg_builder_append_u64(&in_builder, value->qw2);
		tyche_pv_iommu_arg_builder_append_u64(&in_builder, value->qw3);
	}
	
	res = tyche_pv_iommu(TYCHE_PV_IOMMU_QI_DESC_WRITE, &(in_builder.buf),NULL);
	if(res) {
		BUG();
	}
}
#endif

//shared


void qinval_reclaim_free_desc(struct q_inval *self)
{
	while (self->desc_status[self->free_tail] == QI_DONE ||
	       self->desc_status[self->free_tail] == QI_ABORT) {
		self->desc_status[self->free_tail] = QI_FREE;
		self->free_tail = (self->free_tail + 1) % QI_LENGTH;
		self->free_cnt++;
	}
}

volatile int* qinval_desc_status_ptr(struct q_inval* self) {
    return self->desc_status;
}

raw_spinlock_t* qinval_lock_ptr(struct q_inval* self) {
	return &self->q_lock;
}

int qinval_get_free_head(struct q_inval* self) {
	return self->free_head;
}
void qinval_set_free_head(struct q_inval* self, int value) {
	self->free_head = value;
}

int qinval_get_free_tail(struct q_inval* self) {
	return self->free_tail;
}
void qinval_set_free_tail(struct q_inval* self, int value) {
	self->free_tail = value;
}

int qinval_get_free_cnt(struct q_inval* self) {
	return self->free_cnt;
}
void qinval_set_free_cnt(struct q_inval* self, int value) {
	self->free_cnt = value;
}