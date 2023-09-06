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

extern int driver_create_domain(domain_handle_t handle, driver_domain_t **ptr);
extern int driver_set_traps(driver_domain_t *dom, usize traps);
extern int driver_set_cores(driver_domain_t *dom, usize core_map);
extern int driver_set_perm(driver_domain_t *dom, usize perm);
extern int driver_set_switch(driver_domain_t *dom, usize sw);
extern int driver_set_entry_on_core(driver_domain_t *dom, usize core, usize cr3, usize rip, usize rsp);
extern int driver_commit_domain(driver_domain_t *dom);
extern int driver_vmread(driver_domain_t *dom, usize field, usize *value);
extern int driver_vmwrite(driver_domain_t *dom, usize field, usize value);
extern int driver_vmclear(driver_domain_t *dom, usize phys_addr);
extern int driver_vmptrld(driver_domain_t *dom, usize phys_addr);
extern int driver_invvpid(driver_domain_t *dom, unsigned long ext, u16 vpid, gva_t gva);
extern int driver_invept(driver_domain_t *dom, unsigned long ext, u64 eptp, gpa_t gpa);

int tyche_create_domain(domain_handle_t handle, driver_domain_t **ptr)
{
	return driver_create_domain(handle, ptr);
}

int tyche_set_traps(driver_domain_t *dom, usize traps)
{
	return driver_set_traps(dom, traps);
}

int tyche_set_cores(driver_domain_t *dom, usize core_map)
{
	return driver_set_cores(dom, core_map);
}

int tyche_set_perm(driver_domain_t *dom, usize perm)
{
	return driver_set_perm(dom, perm);
}

int tyche_set_switch(driver_domain_t *dom, usize sw)
{
	return driver_set_switch(dom, sw);
}

int tyche_set_entry_on_core(driver_domain_t *dom, usize core, usize cr3, usize rip, usize rsp)
{
	return driver_set_entry_on_core(dom, core, cr3, rip, rsp);
}

int tyche_commit_domain(driver_domain_t *dom)
{
	return driver_commit_domain(dom);
}

__always_inline int tyche_vmread(driver_domain_t *dom, usize field)
{
	usize val;

	printk(KERN_ERR "tyche_vmread: start\n");
	driver_vmread(dom, field, &val);
	printk(KERN_ERR "tyche_vmread: val=%llu\n", val);

	return val;
}

__always_inline int tyche_vmwrite(driver_domain_t *dom, usize field, usize value)
{
	return driver_vmwrite(dom, field, value);
}

__always_inline int tyche_vmclear(driver_domain_t *dom, usize phys_addr)
{
	return driver_vmclear(dom, phys_addr);
}

__always_inline int tyche_vmptrld(driver_domain_t *dom, usize phys_addr)
{
	return driver_vmptrld(dom, phys_addr);
}

__always_inline int tyche_invvpid(driver_domain_t *dom, unsigned long ext, u16 vpid, gva_t gva)
{
	return driver_invvpid(dom, ext, vpid, gva);
}

__always_inline int tyche_invept(driver_domain_t *dom, unsigned long ext, u64 eptp, gpa_t gpa)
{
	return driver_invept(dom, ext, eptp, gpa);
}

__always_inline int tyche_vmlaunch(driver_domain_t *dom)
{
	return driver_vmlaunch(dom);
}
