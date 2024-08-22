# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I $(srctree)/drivers/tyche/libraries/common/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/dll/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/pts/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/capabilities/include


obj-$(CONFIG_DMAR_TABLE) += dmar.o iommu_tyche_pv_wrapper.o q_inval_pv.o
obj-$(CONFIG_INTEL_IOMMU) += iommu.o pasid.o
obj-$(CONFIG_DMAR_TABLE) += trace.o cap_audit.o
obj-$(CONFIG_DMAR_PERF) += perf.o
obj-$(CONFIG_INTEL_IOMMU_DEBUGFS) += debugfs.o
obj-$(CONFIG_INTEL_IOMMU_SVM) += svm.o
obj-$(CONFIG_IRQ_REMAP) += irq_remapping.o
