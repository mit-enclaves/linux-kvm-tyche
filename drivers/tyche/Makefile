# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for Tyche driver
#

TARGET_MODULE:=tyche

ccflags-y += -I $(srctree)/drivers/tyche/include 
ccflags-y += -I $(srctree)/drivers/tyche/libraries/common/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/dll/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/pts/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/capabilities/include

obj-y += $(TARGET_MODULE).o
$(TARGET_MODULE)-objs += src/driver.o src/ioctl.o src/domains.o src/capabilities.o
$(TARGET_MODULE)-objs += libraries/pts/src/lib.o  libraries/pts/src/x86_64_pt.o
$(TARGET_MODULE)-objs += libraries/capabilities/src/ecs.o  libraries/capabilities/src/lib.o  libraries/capabilities/src/tyche_api.o
