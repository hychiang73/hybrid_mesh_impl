/*
 *	HMC misc functions
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

#include "hmc.h"

struct proc_dir_entry *proc_dir_hmc;

void hmc_print_skb(struct sk_buff *skb, const char *type)
{
	size_t len;
	int rowsize = 16;
	int i, l, linelen, remaining;
	int li = 0;
	u8 *data, ch;

	if (hmc_debug) {
		data = (u8 *)skb_mac_header(skb);
		//data = (u8 *) skb->head;

		if (skb_is_nonlinear(skb))
			len = skb->data_len;
		else
			len = skb->len;

		if (len > 256)
			len = 256;

		remaining = len + 2;
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
	}
}
EXPORT_SYMBOL(hmc_print_skb);

static void print_fdb_info(struct hmc_fdb_entry *f)
{
	hmc_info("=====================================\n");
	hmc_info("f->dst = %pM", f->addr);
	hmc_info("f->sn = %d\n", f->sn);
	hmc_info("f->metric = %d\n", f->metric);
	hmc_info("f->flags = %d\n", f->flags);
	hmc_info("f->iface_id = %d\n", f->iface_id);
}

static void print_mpath_info(struct mesh_path *p)
{
	hmc_info("=====================================\n");
	hmc_info("wlan mesh dst = %x.%x.%x.%x.%x.%x\n", p->dst[0], p->dst[1], p->dst[2], p->dst[3], p->dst[4], p->dst[5]);
	hmc_info("wlan mesh sn = %d\n", p->sn);
	hmc_info("wlan mesh metric = %d\n", p->metric);
	hmc_info("wlan mesh flags = %d\n", p->flags);
}

static void print_ppath_info(struct ak60211_mesh_path *p)
{
	hmc_info("=====================================\n");
	hmc_info("plc mesh dst = %x.%x.%x.%x.%x.%x\n", p->dst[0], p->dst[1], p->dst[2], p->dst[3], p->dst[4], p->dst[5]);
	hmc_info("plc mesh sn = %d\n", p->sn);
	hmc_info("plc mesh metric = %d\n", p->metric);
	hmc_info("plc mesh flags = %d\n", p->flags);
}

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

void test_hmc_gen_pkt(enum hmc_port_egress egress)
{
	struct sk_buff *new_sk;
	struct ethhdr *ether;
	const u8 eth_mac[ETH_ALEN] = {0x00, 0x04, 0x4b, 0xe6, 0xec, 0x3d};
	const u8 wlan_mac[ETH_ALEN] = {0x00, 0x19, 0x94, 0x38, 0xfd, 0x8e};
	u8 broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u8 da[ETH_ALEN] = {0};
	u8 *pos, len = 100;
	int i;
	struct hmc_core *hmc = to_get_hmc();

	hmc_info("test egress = %d\n", egress);

	if (egress == HMC_PORT_PLC)
		memcpy(da, eth_mac, ETH_ALEN);
	else if (egress == HMC_PORT_WIFI)
		memcpy(da, wlan_mac, ETH_ALEN);
	else if (egress == HMC_PORT_FLOOD)
		memcpy(da, broadcast, ETH_ALEN);
	else if (egress == HMC_PORT_BEST)
		memcpy(da, eth_mac, ETH_ALEN);
	else {
		hmc_err("Unknown egress id\n");
		return;
	}


	new_sk = dev_alloc_skb(128);

	skb_reserve(new_sk, 2);

	ether = (struct ethhdr *)skb_put(new_sk, ETH_HLEN);
	memset(ether, 0, ETH_HLEN);

	memcpy(ether->h_dest, da, ETH_ALEN);
	memcpy(ether->h_source, hmc->br_addr, ETH_ALEN);
	ether->h_proto = ntohs(0xAA55);

	pos = skb_put(new_sk, len);

	for (i = 0; i < len; i++)
		*pos++ = 100 + i;

	skb_reset_mac_header(new_sk);

	hmc_xmit(new_sk, egress);
}

static ssize_t br_hmc_proc_test_read(struct file *filp, char __user *buf, size_t size, loff_t *pos)
{
	if (*pos != 0)
		return 0;

	hmc_debug = !hmc_debug;
	hmc_info(" %s debug  = %x\n", hmc_debug ? "Enable" : "Disable", hmc_debug);

	return 0;
}

static ssize_t br_hmc_proc_test_write(struct file *filp, const char *buff, size_t size, loff_t *pos)
{
	int i, count = 0;
	char cmd[512] = {0};
	char *token = NULL, *cur = NULL;
	u32 *data = NULL;
	u8 da[ETH_ALEN] = {0};
	struct nl60211_mesh_info info[HMC_MAX_NODES] = {0};
	struct hmc_fdb_entry *f;

	if ((size - 1) > sizeof(cmd)) {
		hmc_err("ERROR! input length is larger than local buffer\n");
		return -1;
	}

	if (buff != NULL) {
		if (copy_from_user(cmd, buff, size - 1)) {
			hmc_info("Failed to copy data from user space\n");
			return -1;
		}
	}

	hmc_info("size = %d, cmd = %s\n", (int)size, cmd);

	token = cur = cmd;

	data = kcalloc(512, sizeof(u32), GFP_KERNEL);

	while ((token = strsep(&cur, ",")) != NULL) {
		data[count] = str2hex(token);
		hmc_info("data[%d] = %x\n", count, data[count]);
		count++;
	}

	hmc_info("cmd = %s\n", cmd);

	if (strncmp(cmd, "add_tbl", strlen(cmd)) == 0) {
		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];

		f = hmc_fdb_insert(da, data[i+1]);
		if (CHECK_MEM(f)) {
			hmc_err("path is not added\n");
			goto out;
		}

		print_fdb_info(f);

	} else if (strncmp(cmd, "del_tbl", strlen(cmd)) == 0) {
		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];

		if (hmc_fdb_del(da, data[i+1]) < 0)
			hmc_info("Not found the dest from table\n");

	} else if (strncmp(cmd, "lookup_tbl", strlen(cmd)) == 0) {
		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];

		f = hmc_fdb_lookup(da, data[i+1]);
		if (CHECK_MEM(f))
			goto out;

		print_fdb_info(f);

	} else if (strncmp(cmd, "dump_tbl", strlen(cmd)) == 0) {
		if (hmc_ops_fdb_dump(info, HMC_MAX_NODES) < 0) {
			hmc_err("info size is overflow\n");
			goto out;
		}
		for (i = 0; i < HMC_MAX_NODES; i++) {
			if (info[i].iface_id == 0)
				continue;

			hmc_info("info dst = %pM\n", info[i].dst);
			hmc_info("info sn = %d\n", info[i].sn);
			hmc_info("info metric = %d\n", info[i].metric);
			hmc_info("info flags = %d\n", info[i].flags);
			hmc_info("info iface_id = %d\n", info[i].iface_id);
			hmc_info("==================\n");
		}
	} else if (strncmp(cmd, "xmit", strlen(cmd)) == 0) {
		test_hmc_gen_pkt(data[1]);
	} else if (strncmp(cmd, "lookup_best", strlen(cmd)) == 0) {
		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];

		f = hmc_fdb_lookup_best(da);
		if (!f) {
			hmc_err("DA is not found\n");
			goto out;
		}
		print_fdb_info(f);
	} else if (strncmp(cmd, "lookup_wpath", strlen(cmd)) == 0) {
		struct mesh_path *mpath;

		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];
		
		mpath = hmc_wpath_lookup(da);
		if (!mpath) {
			hmc_err("path is not found\n");
			goto out;
		}
		print_mpath_info(mpath);
	} else if (strncmp(cmd, "lookup_ppath", strlen(cmd)) == 0) {
		struct ak60211_mesh_path *ppath;

		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];
		
		ppath = hmc_ppath_lookup(da);
		if (!ppath) {
			hmc_err("path is not found\n");
			goto out;
		}
		print_ppath_info(ppath);
	} else if (strncmp(cmd, "mody_plc_metric", strlen(cmd)) == 0) {
		struct ak60211_mesh_path *ppath;

		for (i = 0; i < ETH_ALEN; i++)
			da[i] = data[i+1];
		
		ppath = hmc_ppath_lookup(da);
		if (!ppath) {
			hmc_err("path is not found\n");
			goto out;
		}
		print_ppath_info(ppath);
		ppath->metric = data[i+1];
		hmc_info("modified da = %pM, metric = %d\n", da, ppath->metric);
		hmc_path_update(da,ppath->metric, ppath->sn, ppath->flags, HMC_PORT_PLC);
	}

out:
	kfree(data);
	return size;
}

const struct file_operations proc_test_fops = {
	.write = br_hmc_proc_test_write,
	.read = br_hmc_proc_test_read,
};

int hmc_misc_init(void)
{
	struct proc_dir_entry *node;

	proc_dir_hmc = proc_mkdir("dicky", NULL);

	node = proc_create("test", 0644, proc_dir_hmc, &proc_test_fops);
	if (!node)
		return -ENODEV;

	return 0;
}

void hmc_misc_exit(void)
{
	remove_proc_entry("test", proc_dir_hmc);
	remove_proc_entry("dicky", NULL);
}