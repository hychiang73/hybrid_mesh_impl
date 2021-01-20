/*
 *	Communicating with Hybrid Mesh Core
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
#include <linux/ieee80211.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/neighbour.h>
#include <linux/export.h>
#include <linux/rculist.h>

#include "br_private.h"
#include "../mac80211/mhmc.h"

#define HMC_PLC_IFACE   "eth0"
#define HMC_WIFI_IFACE  "mesh0"

struct proc_dir_entry *proc_dir_hmc;
struct net_bridge_hmc br_hmc;
struct net_device *hmc_local_dev;

void test_hmc_gen_pkt(void)
{
	struct sk_buff *new_sk;
	struct ethhdr *ether;
	struct net_bridge_hmc plc;
	//const u8 da[ETH_ALEN] = {0x00, 0x04, 0x4b, 0xe6, 0xec, 0x3d};
	//const u8 da[ETH_ALEN] = {0x00, 0x19, 0x94, 0x38, 0xfd, 0x8e};
	const u8 da[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	//const u8 sa[ETH_ALEN] = {0x00, 0x04, 0x4b, 0xec, 0x28, 0x3b};
	const u8 sa[ETH_ALEN] = {0x00, 0x19, 0x94, 0x38, 0xfd, 0x82};
	u8 *pos, len = 100;
	int i;

	BR_TRACE();

	new_sk = dev_alloc_skb(128);

	skb_reserve(new_sk, 2);

	ether = (struct ethhdr *)skb_put(new_sk, ETH_HLEN);
	memset(ether, 0, ETH_HLEN);

	memcpy(ether->h_dest, da, ETH_ALEN);
	memcpy(ether->h_source, sa, ETH_ALEN);
	ether->h_proto = ntohs(0xAA55);

	pos = skb_put(new_sk, len);

	for (i = 0; i < len; i++)
		*pos++ = 100 + i;

	skb_reset_mac_header(new_sk);

	br_hmc_print_skb(new_sk, "test_hmc_gen_pkt", 0);

	plc.egress = HMC_PORT_WIFI;

	br_hmc_forward(new_sk, &plc);
}

static ssize_t hmc_proc_test_read(struct file *filp, char __user *buf, size_t size, loff_t *pos)
{
	if (*pos != 0)
		return 0;

	pr_info("*** BR-HMC tx test\n");
	test_hmc_gen_pkt();
	return 0;
}

static ssize_t hmc_proc_test_write(struct file *filp, const char *buff, size_t size, loff_t *pos)
{
	return size;
}

const struct file_operations proc_test_fops = {
	.read = hmc_proc_test_read,
	.write = hmc_proc_test_write,
};

void br_hmc_print_skb(struct sk_buff *skb, const char *type, int offset)
{
	size_t len;
	int rowsize = 16;
	int i, l, linelen, remaining;
	int li = 0;
	u8 *data, ch;

	data = (u8 *)skb_mac_header(skb);
	//data = (u8 *) skb->head;

	if (skb_is_nonlinear(skb))
		len = skb->data_len;
	else
		len = skb->len;

	if (len > 256)
		len = 256;

	remaining = len + 2 + offset;
	pr_info("Packet hex dump (len = %ld):\n", len);
	pr_info("============== %s ==============\n", type);
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
	pr_info("====================================\n");
}
EXPORT_SYMBOL(br_hmc_print_skb);

void br_hmc_net_info(struct sk_buff *skb)
{
	struct net_bridge_port *port;

	port = br_port_get_rcu(skb->dev);
	br_hmc_info("port->name = %s\n", port->dev->name);
}

/* Refer to br_dev_queue_push_xmit in br_forward.c */
int br_hmc_forward(struct sk_buff *skb, struct net_bridge_hmc *hmc)
{
	struct net_bridge *br;
	struct net_bridge_port *p;

	BR_TRACE();

	if (!hmc || !skb) {
		br_hmc_err("hmc or skb is null");
		return -ENOMEM;
	}

	br = netdev_priv(hmc_local_dev);

	rcu_read_lock();

	list_for_each_entry(p, &br->port_list, list) {
		if (hmc->egress == HMC_PORT_FLOOD || 
			(hmc->egress == HMC_PORT_PLC && (strncmp(p->dev->name, HMC_PLC_IFACE, strlen(HMC_PLC_IFACE)) == 0)) ||
			(hmc->egress == HMC_PORT_WIFI && (strncmp(p->dev->name, HMC_WIFI_IFACE, strlen(HMC_WIFI_IFACE)) == 0))) {
			pr_info("Forward to %s iface\n", p->dev->name);
			skb->dev = p->dev;
			dev_queue_xmit(skb);
		}
	}

	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(br_hmc_forward);

/* called by br_handle_frame in br_input.c */
int br_hmc_rx_handler(struct sk_buff *skb)
//int br_hmc_rx_handler(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_hmc *hmc, *n;

	BR_TRACE();

	br_hmc_print_skb(skb, "br_hmc_rx_handler", 0);
	br_hmc_net_info(skb);

	list_for_each_entry_safe(hmc, n, &br_hmc.list, list) {
		if (hmc->ops->rx) {
			if (hmc->ops->rx(skb) < 0)
				return -1;
		}
	}
	return 0;
}

struct net_bridge_hmc *br_hmc_alloc(struct net_bridge_hmc_ops *ops)
{
	struct net_bridge_hmc *hmc;

	hmc = kmalloc(sizeof(*hmc), GFP_KERNEL);
	if (!hmc) {
		br_hmc_err("Failed to allocate mem for hmc\n");
		return NULL;
	}

	memcpy(hmc->br_addr, hmc_local_dev->dev_addr, ETH_ALEN);
	hmc->egress = HMC_PORT_FLOOD;
	hmc->ops = ops;

	list_add(&hmc->list, &br_hmc.list);

	return hmc;
}
EXPORT_SYMBOL(br_hmc_alloc);

void br_hmc_dealloc(void)
{
	struct net_bridge_hmc *p, *n;

	BR_TRACE();

	list_for_each_entry_safe(p, n, &br_hmc.list, list) {
		list_del(&p->list);
		kfree(p);
	}
}
EXPORT_SYMBOL(br_hmc_dealloc);

void br_hmc_notify(int cmd, struct net_device *dev)
{
	BR_TRACE();

	switch (cmd) {
	case HMC_ADD_BR:
		if (!hmc_local_dev)
			hmc_local_dev = NULL;
		hmc_local_dev = dev;
		break;
	case HMC_ADD_IF:
		break;
	};
}

static int test_hmc_proc_create(void)
{
	int ret = 0;
	struct proc_dir_entry *node;

	proc_dir_hmc = proc_mkdir("dicky", NULL);

	node = proc_create("test", 0644, proc_dir_hmc, &proc_test_fops);
	if (!node) {
		pr_info("Failed to create proc node");
		ret = -ENODEV;
	}

	return ret;
}

int br_hmc_init(void)
{
	int ret = 0;

	BR_TRACE();

	test_hmc_proc_create();

	INIT_LIST_HEAD(&br_hmc.list);

	return ret;
}

void br_hmc_deinit(void)
{
	BR_TRACE();
	remove_proc_entry("test", proc_dir_hmc);
	remove_proc_entry("dicky", NULL);
}
