/*
 *	BR-HMC Misc functions
 *
 *	Authors:
 *	Dicky Chiang		<chiang@akiranet.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#include <linux/slab.h>
#include <linux/kernel.h>
#include <net/arp.h>
#include <net/ip.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/random.h>

#include "br_hmc.h"
#include "br_private.h"

struct proc_dir_entry *proc_dir_hmc;

void br_hmc_print_skb(struct sk_buff *skb, const char *type, int offset)
{
	size_t len;
	int rowsize = 16;
	int i, l, linelen, remaining;
	int li = 0;
	u8 *data, ch;

	if (br_hmc_debug) {
		data = (u8 *)skb_mac_header(skb);
		//data = (u8 *) skb->head;

		if (skb_is_nonlinear(skb))
			len = skb->data_len;
		else
			len = skb->len;

		if (len > 256)
			len = 256;

		remaining = len + 2 + offset;
		pr_info("============== %s (len = %ld) ==============\n", type, len);
		for (i = 0; i < len; i += rowsize) {
			pr_info("%06d\t", li);

			linelen = min(remaining, rowsize);
			remaining -= rowsize;

			for (l = 0; l < linelen; l++) {
				ch = data[l];
				pr_cont("%02X ", (uint32_t)ch);
			}

			data += linelen;
			li += 10;

			pr_cont("\n");
		}
		pr_info("===============================================\n");
	}
}
EXPORT_SYMBOL(br_hmc_print_skb);

static int str2hex(char *str)
{
	int strlen, result, intermed, intermedtop;
	char *s = str;

	while (*s != 0x0) {
		s++;
	}

	strlen = (int)(s - str);
	s = str;
	if (*s != 0x30) {
		return -1;
	}

	s++;

	if (*s != 0x78 && *s != 0x58) {
		return -1;
	}
	s++;

	strlen = strlen - 3;
	result = 0;
	while (*s != 0x0) {
		intermed = *s & 0x0f;
		intermedtop = *s & 0xf0;
		if (intermedtop == 0x60 || intermedtop == 0x40) {
			intermed += 0x09;
		}
		intermed = intermed << (strlen << 2);
		result = result | intermed;
		strlen -= 1;
		s++;
	}
	return result;
}

static ssize_t br_hmc_proc_test_read(struct file *filp, char __user *buf, size_t size, loff_t *pos)
{
	if (*pos != 0)
		return 0;

	br_hmc_debug = !br_hmc_debug;
	br_hmc_info(" %s debug  = %x\n", br_hmc_debug ? "Enable" : "Disable", br_hmc_debug);

	return 0;
}

static ssize_t br_hmc_proc_test_write(struct file *filp, const char *buff, size_t size, loff_t *pos)
{
	int count = 0;
	char cmd[512] = {0};
	char *token = NULL, *cur = NULL;
	u32 *data = NULL;
	const u8 da[ETH_ALEN] = {0x00, 0x04, 0x4b, 0xe6, 0xec, 0x3d};

	if ((size - 1) > sizeof(cmd)) {
		br_hmc_err("ERROR! input length is larger than local buffer\n");
		return -1;
	}

	if (buff != NULL) {
		if (copy_from_user(cmd, buff, size - 1)) {
			br_hmc_info("Failed to copy data from user space\n");
			return -1;
		}
	}

	br_hmc_info("size = %d, cmd = %s\n", (int)size, cmd);

	token = cur = cmd;

	data = kcalloc(512, sizeof(u32), GFP_KERNEL);

	while ((token = strsep(&cur, ",")) != NULL) {
		data[count] = str2hex(token);
		br_hmc_info("data[%d] = %x\n", count, data[count]);
		count++;
	}

	br_hmc_info("cmd = %s\n", cmd);

	if (strncmp(cmd, "add_tbl", strlen(cmd)) == 0) {
		br_hmc_path_add(da);
	} else if (strncmp(cmd, "del_tbl", strlen(cmd)) == 0) {
		br_hmc_path_del(da);
	} else if (strncmp(cmd, "lookup_tbl", strlen(cmd)) == 0) {
		br_hmc_path_lookup(da);
	}

	kfree(data);
	return size;
}

const struct file_operations proc_test_fops = {
	.write = br_hmc_proc_test_write,
	.read = br_hmc_proc_test_read,
};

int br_hmc_misc_init(void)
{
	struct proc_dir_entry *node;

	proc_dir_hmc = proc_mkdir("dicky", NULL);

	node = proc_create("test", 0644, proc_dir_hmc, &proc_test_fops);
	if (!node)
		return -ENODEV;

	return 0;
}

void br_hmc_misc_exit(void)
{
	remove_proc_entry("test", proc_dir_hmc);
	remove_proc_entry("dicky", NULL);
}