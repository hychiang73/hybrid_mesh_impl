/*
 *	Hybrid mesh core (HMC) implementations
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
#include <linux/module.h>
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

#include "hmc.h"

/* debug */
bool hmc_debug = false;
EXPORT_SYMBOL(hmc_debug);

static struct kmem_cache *hmc_fdb_cache __read_mostly;
static u32 fdb_salt __read_mostly;

struct hmc_core *hmc = NULL;

struct hmc_core *hmc_to_core(void)
{
	return hmc;
}

static inline int hmc_mac_hash(const u8 *mac, u16 iface_id)
{
	u32 key = get_unaligned((u32 *)(mac + 2));
	return jhash_2words(key, iface_id, fdb_salt) & (HMC_HASH_SIZE - 1);
}

static void fdb_discard_frame(struct sk_buff *skb)
{
	kfree_skb(skb);
}

static void fdb_flush_tx_pending(struct hmc_fdb_entry *fdb)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&fdb->frame_queue)) != NULL) {
		skb = skb_dequeue(&fdb->frame_queue);
		hmc_xmit(skb, fdb->iface_id);
	}
}

static void fdb_flush_pending(struct hmc_fdb_entry *fdb)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&fdb->frame_queue)) != NULL)
		fdb_discard_frame(skb);
}

static struct hmc_fdb_entry *fdb_find(struct hlist_head *head, const u8 *addr, u16 iface_id)
{
	struct hmc_fdb_entry *fdb;

	hlist_for_each_entry(fdb, head, hlist) {
		if (ether_addr_equal(fdb->addr, addr) && fdb->iface_id == iface_id)
			return fdb;
	}
	return NULL;
}

static int fdb_delete(const u8 *addr, u16 iface_id)
{
	struct hlist_head *head = &hmc->hash[hmc_mac_hash(addr, iface_id)];
	struct hmc_fdb_entry *fdb;

	fdb = fdb_find(head, addr, iface_id);
	if (CHECK_MEM(fdb))
		return -ENOENT;

	hlist_del_rcu(&fdb->hlist);
	fdb_flush_pending(fdb);
	kmem_cache_free(hmc_fdb_cache, fdb);

	return 0;
}

static struct hmc_fdb_entry *fdb_create(struct hlist_head *head, const u8 *addr, u16 iface_id)
{
	struct hmc_fdb_entry *fdb;

	fdb = kmem_cache_alloc(hmc_fdb_cache, GFP_ATOMIC);
	if (!CHECK_MEM(fdb)) {
		memcpy(fdb->addr, addr, ETH_ALEN);
		skb_queue_head_init(&fdb->frame_queue);
		fdb->iface_id = iface_id;
		fdb->sn = 0;
		fdb->metric = 0;
		fdb->flags = 0;
		fdb->exp_time = jiffies;
		hlist_add_head_rcu(&fdb->hlist, head);
	}
	return fdb;
}

static struct hmc_fdb_entry *fdb_insert(const u8 *addr, u16 iface_id)
{
	struct hlist_head *head = &hmc->hash[hmc_mac_hash(addr, iface_id)];
	struct hmc_fdb_entry *fdb;

	if (!is_valid_ether_addr(addr))
		return NULL;

	if (is_zero_ether_addr(addr))
		return NULL;

	fdb = fdb_find(head, addr, iface_id);
	if (CHECK_MEM(fdb)) {
		fdb = fdb_create(head, addr, iface_id);
		if (CHECK_MEM(fdb))
			return NULL;
	}
	return fdb;
}

static bool fdb_expired(struct hmc_fdb_entry *f)
{
	return (f->flags & MESH_PATH_ACTIVE) &&
	       time_after(jiffies, f->exp_time + hmc->aging_time);
}

int hmc_fdb_del(const u8 *addr, u16 iface_id)
{
	int ret;

	HMC_TRACE();

	spin_lock_bh(&hmc->hash_lock);

	ret = fdb_delete(addr, iface_id);

	spin_unlock_bh(&hmc->hash_lock);
	return ret;
}
EXPORT_SYMBOL(hmc_fdb_del);

struct hmc_fdb_entry *hmc_fdb_insert(const u8 *addr, u16 iface_id)
{
	int id = iface_id;
	struct hmc_fdb_entry *fdb;

	HMC_TRACE();

	if (id == 0)
		id = HMC_PORT_PLC;

	spin_lock_bh(&hmc->hash_lock);

	fdb = fdb_insert(addr, id);

	spin_unlock_bh(&hmc->hash_lock);
	return fdb;
}
EXPORT_SYMBOL(hmc_fdb_insert);

struct hmc_fdb_entry *hmc_fdb_lookup(const u8 *addr, u16 iface_id)
{
	struct hlist_head *head = &hmc->hash[hmc_mac_hash(addr, iface_id)];
	struct hmc_fdb_entry *fdb;

	spin_lock_bh(&hmc->hash_lock);

	fdb = fdb_find(head, addr, iface_id);

	spin_unlock_bh(&hmc->hash_lock);

	return fdb;
}
EXPORT_SYMBOL(hmc_fdb_lookup);

struct hmc_fdb_entry *hmc_fdb_lookup_best(const u8 *addr)
{
	int i, cnt = 0;
	struct hmc_fdb_entry *f = NULL, *plc = NULL, *wlan = NULL;

	for (i = 0; i < HMC_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, &hmc->hash[i], hlist) {
			if (!is_valid_ether_addr(f->addr) || is_zero_ether_addr(f->addr))
				continue;

			if (f->iface_id == HMC_PORT_PLC) {
				plc = f;
				cnt++;
			} else if (f->iface_id == HMC_PORT_WIFI) {
				wlan = f;
				cnt++;
			}
		}
	}
	
	hmc_info("p = %p, w = %p\n", plc, wlan);

	if (!plc && !wlan)
		return NULL;
	else if (!plc)
		return wlan;
	else if (!wlan)
		return plc;
	else {
		hmc_info("pm = %d, wm = %d\n", plc->metric, wlan->metric);
		if (plc->metric <= wlan->metric)
			return plc;
		else
			return wlan;
	}
}
EXPORT_SYMBOL(hmc_fdb_lookup_best);

int hmc_fdb_dump(struct nl60211_mesh_info *info, int size)
{
	int i = 0, idx = 0;
	struct hmc_fdb_entry *f;

	spin_lock_bh(&hmc->hash_lock);

	for (i = 0; i < HMC_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, &hmc->hash[i], hlist) {
			if (!is_valid_ether_addr(f->addr) || is_zero_ether_addr(f->addr))
				continue;

			if (f->iface_id == HMC_PORT_PLC || f->iface_id == HMC_PORT_WIFI) {
				if (idx > size) {
					spin_unlock_bh(&hmc->hash_lock);
					return -1;
				}

				memcpy(info[idx].dst, f->addr, ETH_ALEN);
				info[idx].metric = f->metric;
				info[idx].sn = f->sn;
				info[idx].flags = f->flags;
				info[idx].iface_id = f->iface_id;
				idx++;
			}
		}
	}

	spin_unlock_bh(&hmc->hash_lock);
	return 0;
}
EXPORT_SYMBOL(hmc_fdb_dump);

struct mesh_path *hmc_wpath_lookup(const u8 *addr)
{
	struct mesh_path *mpath;
	struct ieee80211_sub_if_data *sdata;

	HMC_TRACE();

	sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);

	if (!sdata) {
		hmc_err("mesh priv data is null\n");
		return NULL;
	}

	mpath = mesh_path_lookup(sdata, addr);
	if (!mpath) {
		hmc_err("mesh path is not found\n");
		return NULL;
	}

	return mpath;
}

struct ak60211_mesh_path *hmc_ppath_lookup(const u8 *addr)
{
	struct ak60211_mesh_path *ppath;
	struct ak60211_if_data *pdata;

	HMC_TRACE();

	pdata = ak60211_dev_to_ifdata();
	if (!pdata) {
		hmc_err("mesh priv data is null\n");
		return NULL;		
	}

	ppath = ak60211_mpath_lookup(pdata, addr);
	if (CHECK_MEM(ppath)) {
		hmc_err("mesh path is not found\n");
		return NULL;
	}

	return ppath;
}

static int hmc_wlan_path_resolve(struct hmc_fdb_entry *fdb, const u8 *addr)
{
	struct mesh_path *mpath;
	struct ieee80211_sub_if_data *sdata;

	HMC_TRACE();

	sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);
	if (!sdata) {
		hmc_err("mesh priv data is null\n");
		return -ENODEV;
	}

	mpath = hmc_wpath_lookup(addr);
	if (!mpath) {
		mpath = mesh_path_add(sdata, addr);
		if (IS_ERR(mpath)) {
			hmc_info("Failed to resolved wlan path\n");
			return -EINVAL;
		}
	}

	if (mpath->flags & MESH_PATH_ACTIVE) {
		hmc_info("WIFI mesh path is active, update fdb and flush\n");
		fdb->metric = mpath->metric;
		fdb->sn = mpath->sn;
		fdb->iface_id = HMC_PORT_WIFI;
		fdb->flags = mpath->flags;
		fdb->exp_time = jiffies;
		fdb_flush_tx_pending(fdb);
		return 0;
	}

	if (mpath->flags & MESH_PATH_RESOLVING) {
		hmc_info("WIFI mesh path is resolving ...\n");
		return 0;
	} else {
		hmc_info("Try to resolve wifi mesh path\n");
		mesh_queue_preq(mpath, PREQ_Q_F_START);
	}

	return 0;
}

static int hmc_plc_path_resolve(struct hmc_fdb_entry *fdb, const u8 *addr)
{
	struct ak60211_mesh_path *ppath;

	HMC_TRACE();

	ppath = hmc_ppath_lookup(addr);
	if (CHECK_MEM(ppath)) {
		hmc_err("Couldn't get plc path ... request preq\n");
		plc_hmc_preq_queue(addr);
		return -ENOMEM;
	}

	if (ppath->flags & MESH_PATH_ACTIVE) {
		hmc_info("PLC mesh path is active!\n");
		fdb->metric = ppath->metric;
		fdb->sn = ppath->sn;
		fdb->iface_id = HMC_PORT_PLC;
		fdb->flags = ppath->flags;
		fdb->exp_time = jiffies;
		fdb_flush_tx_pending(fdb);
		return 0;
	}

	if (ppath->flags & MESH_PATH_RESOLVING) {
		hmc_info("PLC mesh path is resolving ...\n");
		return 0;
	} else {
		hmc_info("Try to resolve plc mesh path\n");
		plc_hmc_preq_queue(addr);
	}

	return 0;
}

int hmc_xmit(struct sk_buff *skb, enum hmc_port_egress egress)
{
	int ret = 0;

	if (CHECK_MEM(skb))
		return -ENOMEM;

	mutex_lock(&hmc->xmit_mutex);
	rcu_read_lock();

	hmc_print_skb(skb, "hmc_xmit");

	switch (egress) {
	case HMC_PORT_FLOOD:
		hmc_info("HMC_PORT_FLOOD\n");
		skb->dev = hmc->edev;
		dev_queue_xmit(skb);
		skb->dev = hmc->wdev;
		dev_queue_xmit(skb);		
		break;
	case HMC_PORT_PLC:
		hmc_info("HMC_PORT_PLC\n");
		skb->dev = hmc->edev;
		dev_queue_xmit(skb);
		break;
	case HMC_PORT_WIFI:
		hmc_info("HMC_PORT_WIFI\n");
		skb->dev = hmc->wdev;
		dev_queue_xmit(skb);
		break;
	case HMC_PORT_BEST:
		//memcpy(dest, skb->data, ETH_ALEN);
		/* TODO : forwarding based on metric */
		hmc_info("PORT_BEST not supported yet\n");
		kfree_skb(skb);
		ret = -ENODEV;
		break;
	default:
		hmc_err("Unknow egress\n");
		kfree_skb(skb);
		ret = -EINVAL;
		break;
	}

	rcu_read_unlock();
	mutex_unlock(&hmc->xmit_mutex);
	return ret;
}
EXPORT_SYMBOL(hmc_xmit);

int hmc_br_tx_handler(struct sk_buff *skb)
{
	struct hmc_fdb_entry *fdb;
	struct sk_buff *skb_to_free = NULL;
	u8 dest[ETH_ALEN] = {0};

	skb_reset_mac_header(skb);

	hmc_print_skb(skb, "hmc_br_tx_handler");

	memcpy(dest, skb->data, ETH_ALEN);

	if (!is_valid_ether_addr(dest))
		return NF_DROP;

	fdb = hmc_fdb_lookup_best(dest);
	if (CHECK_MEM(fdb)) {
		fdb = hmc_fdb_insert(dest, 0);
		if (CHECK_MEM(fdb)) {
			hmc_err("Failed to insert dest addr to fdb, discard frames\n");
			fdb_discard_frame(skb);
			return NF_ACCEPT;
		}
	}

	if (fdb && (fdb->flags & MESH_PATH_ACTIVE)) {
		if (!fdb_expired(fdb)) {
			hmc_info("xmit via %d\n", fdb->iface_id);
			hmc_xmit(skb, fdb->iface_id);
			return NF_ACCEPT;
		}
		hmc_info("path is expired ... request to update metric\n");
		hmc_fdb_del(dest, HMC_PORT_PLC);
		hmc_fdb_del(dest, HMC_PORT_WIFI);
	}

	if (hmc_plc_path_resolve(fdb, dest) < 0)
		hmc_err("Failed to resolve plc path\n");

	if (hmc_wlan_path_resolve(fdb, dest) < 0)
		hmc_err("Failed to resolve wlan path\n");

	if (skb_queue_len(&fdb->frame_queue) >= HMC_SKB_QUEUE_LEN)
		skb_to_free = skb_dequeue(&fdb->frame_queue);

	skb_queue_tail(&fdb->frame_queue, skb);

	if (skb_to_free)
		fdb_discard_frame(skb_to_free);

	hmc_info("Tx frame was queued\n");

	return NF_QUEUE;
}

int hmc_br_rx_handler(struct sk_buff *skb)
{
	int ret;

	hmc_print_skb(skb, "hmc_rx_handler");

	mutex_lock(&hmc->rx_mutex);

	/* SNAP data might be inside 802.3 frames even if coming from wifi egress. */
	ret = plc_hmc_rx(skb);

	mutex_unlock(&hmc->rx_mutex);

	/* return to br_handle_frame */
	if (ret == NF_DROP)
		return 0;

	return 1;
}

int hmc_get_dev_addr(u8 *addr)
{
	if (!addr)
		return -1;

	memcpy(addr, hmc->br_addr, ETH_ALEN);
	return 0;
}
EXPORT_SYMBOL(hmc_get_dev_addr);

static const struct nf_br_ops hmc_ops = {
	.br_dev_xmit_hook =	hmc_br_tx_handler,
};

int hmc_fdb_init(void)
{
	hmc_info();

	hmc_fdb_cache = kmem_cache_create("hmc_fdb_cache",
					 sizeof(struct hmc_fdb_entry),
					 0,
					 SLAB_HWCACHE_ALIGN, NULL);
	
	if (CHECK_MEM(hmc_fdb_cache))
		return -ENOMEM;

	get_random_bytes(&fdb_salt, sizeof(fdb_salt));
	return 0;
}

static void hmc_fdb_fini(void)
{
	hmc_info();

	if (hmc_fdb_cache)
		kmem_cache_destroy(hmc_fdb_cache);
}

static void hmc_dev_release(void)
{
	hmc_info("release hybrid mesh core\n");

	if (hmc->bdev)
		dev_put(hmc->bdev);

	if (hmc->edev)
		dev_put(hmc->edev);

	if (hmc->wdev)
		dev_put(hmc->wdev);

	kfree(hmc);
	hmc = NULL;
}

int hmc_core_init(void)
{
	int ret = 0;

	hmc_info("hybrid mesh core init\n");

	hmc = kzalloc(sizeof(*hmc), GFP_KERNEL);
	if (CHECK_MEM(hmc)) {
		hmc_err("Failed to allocate hmc mem\n");
		return -ENOMEM;
	}

	hmc->bdev = dev_get_by_name(&init_net, "br0");
	if (CHECK_MEM(hmc->bdev)) {
		hmc_err("br0 is not to be created\n");
		ret = -ENODEV;
		goto err;
	}

	hmc->edev = dev_get_by_name(&init_net, "eth0");
	if (CHECK_MEM(hmc->edev)) {
		hmc_err("eth0 is not to be created\n");
		ret = -ENODEV;
		goto err;
	}

	hmc->wdev = dev_get_by_name(&init_net, "mesh0");
	if (CHECK_MEM(hmc->wdev)) {
		hmc_err("mesh0 is not to be created\n");
		ret = -ENODEV;
		goto err;
	}

	memcpy(hmc->br_addr, hmc->bdev->dev_addr, ETH_ALEN);
	hmc_info("hmc->br_addr = %x.%x.%x.%x.%x.%x\n", hmc->br_addr[0],hmc->br_addr[1],hmc->br_addr[2], hmc->br_addr[3],hmc->br_addr[4],hmc->br_addr[5]);

	spin_lock_init(&hmc->hash_lock);
	mutex_init(&hmc->rx_mutex);
	mutex_init(&hmc->xmit_mutex);

	hmc->aging_time = HMC_DEF_EXP_TIME;

	ret = hmc_fdb_init();
	if (ret < 0) {
		hmc_err("Failed to create hmc forwarding database\n");
		goto err;
	}

	ret = hmc_misc_init();
	if (ret < 0) {
		hmc_err("Failed to create hmc proc subsys\n");
		goto err;
	}

	/* hook with bridge rx func */
	RCU_INIT_POINTER(br_should_route_hook,
			   (br_should_route_hook_t *)hmc_br_rx_handler);

	/* hook with bridge tx func */
	RCU_INIT_POINTER(nf_br_ops, &hmc_ops);

	return 0;

err:
	hmc_dev_release();
	return ret;
}

void hmc_core_exit(void)
{
	hmc_info("hybrid mesh core exit\n");

	RCU_INIT_POINTER(br_should_route_hook, NULL);

	RCU_INIT_POINTER(nf_br_ops, NULL);

	hmc_misc_exit();

	hmc_fdb_fini();

	if (hmc != NULL) {
		if (hmc->bdev)
			dev_put(hmc->bdev);

		if (hmc->edev)
			dev_put(hmc->edev);

		if (hmc->wdev)
			dev_put(hmc->wdev);

		kfree(hmc);
		hmc = NULL;
	}
}