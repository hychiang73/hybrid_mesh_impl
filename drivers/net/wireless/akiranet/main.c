
#include <linux/module.h>

static int __init ak6e_init(void)
{
	pr_info("Hello ! This is wirless driver for AkiraNET\n");
	return 0;
}
module_init(ak6e_init);

static void __exit ak6e_exit(void)
{
	pr_info("Unloaded ak6e module\n");
}

module_exit(ak6e_exit);

MODULE_AUTHOR("AkiraNET");
MODULE_DESCRIPTION("Driver support for AkiraNET 802.11ax WLAN devices");
MODULE_LICENSE("GPL");
