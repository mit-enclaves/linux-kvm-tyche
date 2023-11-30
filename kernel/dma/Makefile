# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/drivers/tyche/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/common/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/dll/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/capabilities/include

obj-$(CONFIG_HAS_DMA)			+= mapping.o direct.o
obj-$(CONFIG_DMA_OPS)			+= ops_helpers.o
obj-$(CONFIG_DMA_OPS)			+= dummy.o
obj-$(CONFIG_DMA_CMA)			+= contiguous.o
obj-$(CONFIG_DMA_DECLARE_COHERENT)	+= coherent.o
obj-$(CONFIG_DMA_API_DEBUG)		+= debug.o
obj-$(CONFIG_SWIOTLB)			+= swiotlb.o
obj-$(CONFIG_DMA_COHERENT_POOL)		+= pool.o
obj-$(CONFIG_MMU)			+= remap.o
obj-$(CONFIG_DMA_MAP_BENCHMARK)		+= map_benchmark.o
