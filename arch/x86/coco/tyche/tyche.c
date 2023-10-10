#undef pr_fmt
#define pr_fmt(fmt)     "tyche: " fmt

#include <linux/cpufeature.h>
#include <asm/coco.h>

void __init tyche_early_init(void)
{
	cc_vendor = CC_VENDOR_TYCHE;

	pr_info("Guest detected\n");
}
