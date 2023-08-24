#include <linux/nospec.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/slab.h>

#include "tychecall.h"

extern int driver_create_domain(struct file *handle);
extern int driver_set_traps(struct file *handle, unsigned long long traps);
extern int driver_set_cores(struct file *handle, unsigned long long traps);

int tyche_create_domain(struct file *handle)
{
	return driver_create_domain(handle);
}

int tyche_set_traps(struct file *handle, unsigned long long traps)
{
	return driver_set_traps(handle, traps);
}

int tyche_set_cores(struct file *handle, unsigned long long core_map)
{
	return driver_set_cores(handle, core_map);
}
