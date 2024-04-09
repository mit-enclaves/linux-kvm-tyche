# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for Contalloc driver
#

TARGET_MODULE:=contalloc

ccflags-y += -I $(srctree)/drivers/contalloc/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/common/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/dll/include

obj-y += $(TARGET_MODULE).o
$(TARGET_MODULE)-objs += src/driver.o src/ioctl.o src/allocs.o
#$(TARGET_MODULE)-objs += libraries/pts/src/lib.o  libraries/pts/src/x86_64_pt.o
