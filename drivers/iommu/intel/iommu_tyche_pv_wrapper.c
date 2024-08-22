#include "iommu_tyche_pv_wrapper.h"
#include "common_log.h"
#include "linux/kern_levels.h"
#include "tyche_api.h"

static uint64_t iommu_vaddr = 0;


#ifdef NO_TYCHE
void iommu_reg_writel(u32 value,  void* target) 
{
	writel(value, target);
}

void iommu_reg_writeq(u64 value,  void* target)
{
	dmar_writeq(target, value);
}

u32 iommu_reg_readl(void *target)
{
	return readl(iommu->reg + reg_offset);
}

u64 iommu_reg_readq(void* target) {
	return dmar_readq(target);
}

void iommu_tyche_pv_wrapper_init(struct intel_iommu* iommu){/*NOP*/};
#else
void iommu_reg_writel(u32 value,  void* target) 
{
	tyche_pv_iommu_arg_builder_t builder;
	u32 reg_offset;

	if( iommu_vaddr == 0 ) {
		LOG("iommu_vaddr not initialzed");
		BUG();
	}
	reg_offset = ((uint64_t)target)-iommu_vaddr;
	//LOG("iommu_vaddr %013llx , target %013llx, reg_offset %x value %x", iommu_vaddr, (uint64_t)target, reg_offset,value);
	tyche_pv_iommu_arg_builder_init(&builder);
	if(tyche_pv_iommu_arg_builder_append_u32(&builder, reg_offset)) {
		BUG();
	}
	if(tyche_pv_iommu_arg_builder_append_u32(&builder, value)) {
		BUG();
	}
	/*{
		size_t idx;
		printk("%s:%d %s reg_offset %x, builder.buf.as_bytes: ", __FILE__, __LINE__, __FUNCTION__, reg_offset);
		for(idx=0;idx < builder.written; idx++) {
			if(idx == (builder.written -1)) {
				printk(KERN_CONT"%02x\n",builder.buf.as_bytes[idx]);
			}  else {
				printk(KERN_CONT"%02x",builder.buf.as_bytes[idx]);
			}
		}
	}*/
	if (tyche_pv_iommu(TYCHE_PVIOMMU_WRITEL, &(builder.buf), NULL)) {
		LOG("tyche call failed");
		BUG();
	}
}

void iommu_reg_writeq(u64 value,  void* target) 
{
	tyche_pv_iommu_arg_builder_t builder;
	u32 reg_offset;

	if( iommu_vaddr == 0 ) {
		LOG("iommu_vaddr not initialized");
		BUG();
	}
	reg_offset = ((uint64_t)target)-iommu_vaddr;
	
	tyche_pv_iommu_arg_builder_init(&builder);
	if(tyche_pv_iommu_arg_builder_append_u32(&builder, reg_offset)) {
		BUG();
	}
	if(tyche_pv_iommu_arg_builder_append_u64(&builder, value)) {
		BUG();
	}
	/*{
		size_t idx;
		printk("%s:%d %s builder.buf.as_bytes: ", __FILE__, __LINE__, __FUNCTION__);
		for(idx=0;idx < builder.written; idx++) {
			if(idx == (builder.written -1)) {
				printk(KERN_CONT"%02x\n",builder.buf.as_bytes[idx]);
			}  else {
				printk(KERN_CONT"%02x",builder.buf.as_bytes[idx]);
			}
		}
	}*/
	if (tyche_pv_iommu(TYCHE_PVIOMMU_WRITEQ, &(builder.buf), NULL)) {
		LOG("tyche call failed");
		BUG();
	}
}

u32 iommu_reg_readl(void* target) {
	u32 reg_offset;
	u32 out;
	tyche_pv_iommu_arg_builder_t builder;
	tyche_pv_iommu_in_out_buf_u out_buf;

	if(iommu_vaddr == 0 ) {
		LOG("iommu_vaddr not initialized");
		BUG();
	}
	reg_offset = ((uint64_t)target) - iommu_vaddr;
	
	tyche_pv_iommu_arg_builder_init(&builder);
	if(tyche_pv_iommu_arg_builder_append_u32(&builder, reg_offset)) {
		BUG();
	}

	if (tyche_pv_iommu(TYCHE_PV_IOMMU_READL, &(builder.buf), &out_buf)) {
		LOG("tyche call failed");
		BUG();
	}
	memcpy(&out, out_buf.as_bytes, sizeof(u32));
	return out;
}

u64 iommu_reg_readq(void* target) {
	u32 reg_offset;
	u64 out;
	tyche_pv_iommu_arg_builder_t builder;
	tyche_pv_iommu_in_out_buf_u out_buf;

	if(iommu_vaddr == 0 ) {
		LOG("iommu_vaddr not initialized");
		BUG();
	}
	reg_offset = ((uint64_t)target) - iommu_vaddr;
	
	tyche_pv_iommu_arg_builder_init(&builder);
	if(tyche_pv_iommu_arg_builder_append_u32(&builder, reg_offset)) {
		BUG();
	}

	if (tyche_pv_iommu(TYCHE_PV_IOMMU_READQ, &(builder.buf), &out_buf)) {
		LOG("tyche call failed");
		BUG();
	}
	memcpy(&out, out_buf.as_bytes, sizeof(u64));
	return out;
}

void iommu_tyche_pv_wrapper_init(void* iommu_mapping) {
	iommu_vaddr = (uint64_t)iommu_mapping;
	printk("%s:%d %s inialized iommu_vaddr to 0x%llx\n", __FILE__, __LINE__, __FUNCTION__, iommu_vaddr);

}
#endif
