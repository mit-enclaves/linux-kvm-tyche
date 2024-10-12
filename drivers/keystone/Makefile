# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for Keystone driver
#

ccflags-y += -I $(srctree)/drivers/tyche/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/common/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/dll/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/pts/include
ccflags-y += -I $(srctree)/drivers/tyche/libraries/capabilities/include

TARGET_MODULE:=keystone

obj-y += $(TARGET_MODULE).o

$(TARGET_MODULE)-objs += keystone.o keystone-page.o keystone-ioctl.o keystone-enclave.o keystone-sbi.o
