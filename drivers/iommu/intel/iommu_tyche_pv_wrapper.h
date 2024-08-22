#ifndef IOMMU_TYCHE_PV_WRAPPER_H
#define IOMMU_TYCHE_PV_WRAPPER_H
#include "iommu.h"
#include "tyche_api.h"



/**
 * @brief Write to 32 bit value to mmio register via call to Tyche.
 * If built without tyche support, just do mem read
 * 
 * @param value value to write
 * @param target full address of mmio register of iommu
 */
void iommu_reg_writel(u32 value,  void* target);

/**
 * @brief Write to 64 bit value to mmio register via call to Tyche
 * If built without tyche support, just do mem read
 * 
 * @param value value to write
 * @param target full address of mmio register of iommu
 */
void iommu_reg_writeq(u64 value,  void* target);

/**
 * @brief Read 32 bit value from mmio register via call to Tyche
 * If built without tyche support, just do mem read
 * 
 * @param target full address of mmio register of iommu
 */
u32 iommu_reg_readl(void *target);

/**
 * @brief Read 32 bit value from mmio register via call to Tyche
 * If built without tyche support, just do mem read
 * 
 * @param target full address of mmio register of iommu
 */
u64 iommu_reg_readq(void* target);

/**
 * @brief Initialize interface. May be called multiple times but will overwrite
 * the previous initialization. If built wihtout Tyche support, this is a NOP.
 * 
 * @param iommu_mapping virt addr where iommu is mapped
 */
void iommu_tyche_pv_wrapper_init(void* iommu_mapping);

#endif 