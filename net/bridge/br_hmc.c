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
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/random.h>

#include "br_private.h"
#include "br_hmc.h"
#include "../mac60211/mac60211.h"
#include "../mac80211/mhmc.h"

struct hmc_path {
	u8 dst[ETH_ALEN];
	struct rhash_head rhash;
	struct hlist_node walk_list;
	struct sk_buff_head frame_queue;
	u32 sn;
	u32 metric;
	enum br_hmc_path_flags flags;
};

struct hmc_table {
	struct rhashtable rhead;
	struct hlist_head walk_head;
	spinlock_t walk_lock;
	atomic_t entries;
};

struct hmc_table *htbl = NULL;
struct net_bridge_hmc br_hmc;
struct net_device *hmc_local_dev;

/* debug */
bool br_hmc_debug = false;
EXPORT_SYMBOL(br_hmc_debug);

static u32 br_hmc_table_hash(const void *addr, u32 len, u32 seed)
{
	/* Use last four bytes of hw addr as hash index */
	return jhash_1word(__get_unaligned_cpu32((u8 *)addr + 2), seed);
}

static const struct rhashtable_params br_hmc_rht_params = {
	.nelem_hint = 2,
	.automatic_shrinking = true,
	.key_len = ETH_ALEN,
	.key_offset = offsetof(struct hmc_path, dst),
	.head_offset = offsetof(struct hmc_path, rhash),
	.hashfn = br_hmc_table_hash,
};

static struct net_bridge_hmc* __obtain_hmc_iface_id(u8 id)
{
	struct net_bridge_hmc *p, *n;

	list_for_each_entry_safe(p, n, &br_hmc.list, list) {
		if (p->id == id)
			return p;
	}

	return NULL;
}

static void br_hmc_path_tx_queue(struct hmc_path *path, struct net_bridge_hmc *plc)
{
	memcpy(plc->path->dst, path->dst, ETH_ALEN);
	plc->path->sn = path->sn;
	plc->path->flags = path->flags;
	plc->path->metric = path->metric;

	BR_TRACE();

	if (!plc->ops->queue_preq)
		return;

	if (!(path->flags & BR_HMC_PATH_RESOLVING)) {
		br_hmc_info("notify mesh mgmt to send PREQ for resolving\n");
		plc->ops->queue_preq(plc);
	}
}

/* Sends pending frames in a mesh path queue */
static void br_hmc_path_tx_pending(struct hmc_path *path, struct net_bridge_hmc *port)
{
	struct sk_buff *skb;

	BR_TRACE();

	while ((skb = skb_dequeue(&path->frame_queue)) != NULL) {
		skb = skb_dequeue(&path->frame_queue);
		br_hmc_forward(skb, port);
	}
}

static void br_hmc_path_discard_frame(struct sk_buff *skb)
{
	kfree_skb(skb);
}

static void br_hmc_path_flush_pending(struct hmc_path *path)
{
	struct sk_buff *skb;

	if (!path) {
		br_hmc_err("path is not found\n");
		return;
	}

	while ((skb = skb_dequeue(&path->frame_queue)) != NULL)
		br_hmc_path_discard_frame(skb);
}

static void br_hmc_path_free_rcu(struct hmc_table *tbl, struct hmc_path *path)
{
	atomic_dec(&htbl->entries);
	br_hmc_path_flush_pending(path);
}

static void br_hmc_path_rht_free(void *ptr, void *tblptr)
{
	struct hmc_path *free_path = ptr;
	struct hmc_table *free_tbl = tblptr;

	br_hmc_path_free_rcu(free_tbl, free_path);
}

static void br_hmc_table_free(struct hmc_table *tbl)
{
	/* We don't use the parame as table pointer in test. */
	rhashtable_free_and_destroy(&htbl->rhead,
				    br_hmc_path_rht_free, htbl);
	kfree(htbl);
	htbl = NULL;
}

struct hmc_path *br_hmc_path_lookup(const u8 *dst)
{
	struct hmc_path *path;

	path = rhashtable_lookup_fast(&htbl->rhead, dst, br_hmc_rht_params);
	if (!path) {
		br_hmc_err("Not found DA from table\n");
		return NULL;
	}

	return path;
}

struct net_bridge_hmc *br_hmc_iface_id_lookup(u8 id)
{
	struct net_bridge_hmc *h;

	h = __obtain_hmc_iface_id(id);
	if (!h)
		return NULL;

	return h;
}

int br_hmc_mesh_lookup(struct sk_buff *skb)
{
	struct hmc_path *path;
	u8 dest[ETH_ALEN] = {0};

	BR_TRACE();

	memcpy(dest, skb->data, ETH_ALEN);

	/* TODO: lookup wlan table */

	path = br_hmc_path_lookup(dest);
	if (!path || !(path->flags & BR_HMC_PATH_ACTIVE))
		return -ENOENT;

	/* TODO: check plan and wlan mesh metric */
	/* TODO: check mesh expired */
	return 0;
}

int br_hmc_path_del(const u8 *addr)
{
	struct hmc_path *path;

	spin_lock_bh(&htbl->walk_lock);

	path = rhashtable_lookup_fast(&htbl->rhead, addr, br_hmc_rht_params);
	if (CHECK_MEM(path)) {
		spin_unlock_bh(&htbl->walk_lock);
		return -ENXIO;
	}

	hlist_del_rcu(&path->walk_list);
	rhashtable_remove_fast(&htbl->rhead, &path->rhash, br_hmc_rht_params);
	br_hmc_path_free_rcu(htbl, path);

	spin_unlock_bh(&htbl->walk_lock);

	return 0;
}

static struct hmc_path *br_hmc_path_new(const u8 *dst, gfp_t gfp_flags)
{
	struct hmc_path *new_path;

	BR_TRACE();

	new_path = kzalloc(sizeof(struct hmc_path), gfp_flags);
	if (CHECK_MEM(new_path))
		return NULL;

	memcpy(new_path->dst, dst, ETH_ALEN);
	skb_queue_head_init(&new_path->frame_queue);
	new_path->flags = 0;
	new_path->sn = 0;
	new_path->metric = 0;

	return new_path;
}

struct hmc_path *br_hmc_path_add(const u8 *dst)
{
	struct hmc_path *path, *new_path;

	BR_TRACE();

	/* never add ourselves as neighbours */
	if (ether_addr_equal(dst, br_hmc.br_addr))
		return ERR_PTR(-ENOTSUPP);

	if (is_multicast_ether_addr(dst))
		return ERR_PTR(-ENOTSUPP);

	new_path = br_hmc_path_new(dst, GFP_ATOMIC);
	if (!new_path)
		return ERR_PTR(-ENOMEM);

	spin_lock_bh(&htbl->walk_lock);

	path = rhashtable_lookup_get_insert_fast(&htbl->rhead,
							&new_path->rhash,
							br_hmc_rht_params);
	if (!path)
		hlist_add_head(&new_path->walk_list, &htbl->walk_head);

	spin_unlock_bh(&htbl->walk_lock);

	if (path) {
		kfree(new_path);

		if (CHECK_MEM(path))
			return path;

		new_path = path;
	}

	return new_path;
}

int br_hmc_path_update(struct net_bridge_hmc *hmc)
{
	struct hmc_path *path;
	struct net_bridge_hmc *h;

	BR_TRACE();

	h = __obtain_hmc_iface_id(hmc->id);
	if (!h)
		return -1;

	path = br_hmc_path_lookup(h->path->dst);
	if (CHECK_MEM(path))
		return -1;

	path->sn = h->path->sn;
	path->metric = h->path->metric;
	path->flags = h->path->flags;

	br_hmc_info("update BR-HMC table, path->flags = %d\n", path->flags);

	br_hmc_path_tx_pending(path, h);

	return 0;
}
EXPORT_SYMBOL(br_hmc_path_update);

/* Returns: 0 if the DA was found and -ENOENT if the frame was queued. */
int br_hmc_path_solve(struct sk_buff *skb)
{
	struct hmc_path *path = NULL;
	struct sk_buff *skb_to_free = NULL;
	struct net_bridge_hmc *plc = NULL;
	u8 dest[ETH_ALEN] = {0};

	memcpy(dest, skb->data, ETH_ALEN);

	br_hmc_print_skb(skb, "br_hmc_path_solve", 0);

	if (!is_valid_ether_addr(dest))
		return 0;

	if (!br_hmc_mesh_lookup(skb))
		return 0;

	if (!(plc = br_hmc_iface_id_lookup(HMC_PLC_ID)))
		return 0;

	/* no dest found, start resolving */
	path = br_hmc_path_lookup(dest);
	if (!path) {
		br_hmc_info("Not found this path and add it to the table\n");
		path = br_hmc_path_add(dest);
		if (IS_ERR(path)) {
			br_hmc_path_discard_frame(skb);
			return PTR_ERR(path);
		}
	}

	/* TODO: send queue_preq to wlan */
	br_hmc_path_tx_queue(path, plc);

	if (skb_queue_len(&path->frame_queue) >= HMC_FRAME_QUEUE_LEN)
		skb_to_free = skb_dequeue(&path->frame_queue);

	skb_queue_tail(&path->frame_queue, skb);

	if (skb_to_free)
		br_hmc_path_discard_frame(skb_to_free);

	return -ENOENT;
}

/* calling br_dev_queue_push_xmit in br_forward.c for transmission. */
int br_hmc_forward(struct sk_buff *skb, struct net_bridge_hmc *hmc)
{
	int egress;
	struct net_bridge *br;
	struct net_bridge_port *p, *n;

	if (CHECK_MEM(skb))
		return -ENOMEM;

	if (CHECK_MEM(hmc))
		return -ENOMEM;

	egress = hmc->egress;

	br = netdev_priv(hmc_local_dev);

	rcu_read_lock();

	list_for_each_entry_safe(p, n, &br->port_list, list) {
		if (egress == HMC_PORT_FLOOD ||
			(egress == HMC_PORT_PLC && (strncmp(p->dev->name, "eth0", strlen("eth0")) == 0)) ||
			(egress == HMC_PORT_WIFI &&(strncmp(p->dev->name, "mesh0", strlen("mesh0")) == 0))) {
			br_hmc_info("forward to %s\n", p->dev->name);
			br_hmc_print_skb(skb, "br_hmc_forward", 0);
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
{
	struct net_bridge_hmc *p;

	br_hmc_print_skb(skb, "br_hmc_rx_handler", 0);

	p = __obtain_hmc_iface_id(HMC_PLC_ID);
	if (CHECK_MEM(p->ops->rx))
		return 0;

	return p->ops->rx(skb);
}

struct net_bridge_hmc *br_hmc_alloc(const char *name, struct net_bridge_hmc_ops *ops)
{
	struct net_bridge_hmc *hmc;

	hmc = kmalloc(sizeof(*hmc), GFP_KERNEL);
	if (CHECK_MEM(hmc)) {
		br_hmc_err("Failed to allocate mem for hmc\n");
		return NULL;
	}

	hmc->path = kzalloc(sizeof(struct hmc_hybrid_path), GFP_ATOMIC);
	if (CHECK_MEM(hmc->path))
		return NULL;

	if (strncmp("plc", name, strlen(name)) == 0)
		hmc->id = HMC_PLC_ID;
	else if (strncmp("wifi", name, strlen(name)) == 0)
		hmc->id = HMC_WIFI_ID;
	else if (strncmp("nl60211", name, strlen(name)) == 0)
		hmc->id = HMC_NL_ID;
	else
		hmc->id = 0xFF;

	memcpy(hmc->br_addr, hmc_local_dev->dev_addr, ETH_ALEN);
	hmc->egress = HMC_PORT_FLOOD;
	hmc->ops = ops;

	list_add(&hmc->list, &br_hmc.list);

	return hmc;
}
EXPORT_SYMBOL(br_hmc_alloc);

void br_hmc_dealloc(struct net_bridge_hmc *h)
{
	struct net_bridge_hmc *p, *n;

	br_hmc_info("%s", __func__);

	list_for_each_entry_safe(p, n, &br_hmc.list, list) {
		if (p->id == h->id) {
			list_del(&p->list);
			kfree(p);
		}
	}
}
EXPORT_SYMBOL(br_hmc_dealloc);

void br_hmc_notify(int cmd, struct net_device *dev)
{
	switch (cmd) {
	case HMC_ADD_BR:
		if (hmc_local_dev != NULL)
			hmc_local_dev = NULL;
		hmc_local_dev = dev;
		break;
	case HMC_ADD_IF:
		break;
	};
}

static int br_hmc_pathtbl_init(void)
{
	br_hmc_info("%s", __func__);

	htbl = kmalloc(sizeof(struct hmc_table), GFP_ATOMIC);
	if (CHECK_MEM(htbl))
		return -ENOMEM;

	INIT_HLIST_HEAD(&htbl->walk_head);
	atomic_set(&htbl->entries, 0);
	spin_lock_init(&htbl->walk_lock);
	rhashtable_init(&htbl->rhead, &br_hmc_rht_params);

	return 0;
}

int br_hmc_init(void)
{
	br_hmc_info("%s", __func__);

	br_hmc_misc_init();

	INIT_LIST_HEAD(&br_hmc.list);

	br_hmc_pathtbl_init();

	return 0;
}

void br_hmc_deinit(void)
{
	br_hmc_info("%s", __func__);

	br_hmc_misc_exit();

	br_hmc_table_free(htbl);
}
