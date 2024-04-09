#include "contalloc_ioctl.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "common.h"

// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("aghosn");
MODULE_DESCRIPTION("Continuous memory allocator");
MODULE_VERSION("0.01");


// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init contalloc_init(void)
{
  int result = 0;
  printk(KERN_INFO "Loading contalloc driver.");
  result = contalloc_register();
  return result;
}

static void __exit contalloc_exit(void)
{
  printk(KERN_INFO "Removing contalloc driver.");
  contalloc_unregister();
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(contalloc_init);
module_exit(contalloc_exit);
