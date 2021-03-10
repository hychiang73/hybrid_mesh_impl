/*
 *	Hybrid mesh core (HMC) experiment
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

struct hmc_core *to_get_hmc(void)
{
	return hmc;
}
EXPORT_SYMBOL(to_get_hmc);

static inline int hmc_mac_hash(const u8 *mac, u16 iface_id)
{
	u32 key = get_unaligned((u32 *)(mac + 2));
	return jhash_2words(key, iface_id, fdb_salt) & (HMC_HASH_SIZE - 1);
}

#if 0
static bool fdb_expired(struct hmc_fdb_entry *f)
{
	return (f->flags & MESH_PATH_ACTIVE) &&
	       time_after(jiffies, f->exp_time + hmc->aging_time);
}
#endif

static void fdb_discard_frame(struct sk_buff *skb)
{
	HMC_TRACE();

	kfree_skb(skb);
}

#if 0
static void fdb_flush_tx_pending(struct hmc_fdb_entry *fdb)
{
	struct sk_buff *skb;

	HMC_TRACE();

	while ((skb = skb_dequeue(&fdb->frame_queue)) != NULL) {
		skb = skb_dequeue(&fdb->frame_queue);
		if (fdb->iface_id == HMC_PORT_PLC && EN_PLC_ENCAP)
			ak60211_nexthop_resolved(skb, fdb->iface_id);
		else// if (fdb->flags & MESH_PATH_ACTIVE)
			hmc_xmit(skb, fdb->iface_id);
	}
}
#endif

#if 0
static void fdb_flush_pending(struct hmc_fdb_entry *fdb)
{
	struct sk_buff *skb;

	HMC_TRACE();

	while ((skb = skb_dequeue(&fdb->frame_queue)) != NULL)
		fdb_discard_frame(skb);
}
#endif

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

	HMC_TRACE();

	fdb = fdb_find(head, addr, iface_id);
	if (CHECK_MEM(fdb))
		return -ENOENT;

	hlist_del_rcu(&fdb->hlist);
	kmem_cache_free(hmc_fdb_cache, fdb);

	return 0;
}

static struct hmc_fdb_entry *fdb_create(struct hlist_head *head, const u8 *addr, u16 iface_id)
{
	struct hmc_fdb_entry *fdb;

	hmc_dbg("create id : %d, addr : %pM", iface_id, addr);

	fdb = kmem_cache_alloc(hmc_fdb_cache, GFP_ATOMIC);
	if (!CHECK_MEM(fdb)) {
		memcpy(fdb->addr, addr, ETH_ALEN);
		skb_queue_head_init(&fdb->frame_queue);
		fdb->iface_id = iface_id;
		fdb->sn = 0;
		fdb->metric = 0xffffffff;
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

	hmc_dbg("insert id : %d, addr : %pM", iface_id, addr);

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

int hmc_fdb_del(const u8 *addr, u16 iface_id)
{
	int ret;

	hmc_dbg("delete id : %d, addr : %pM", iface_id, addr);

	spin_lock_bh(&hmc->hash_lock);

	ret = fdb_delete(addr, iface_id);

	spin_unlock_bh(&hmc->hash_lock);
	return ret;
}

struct hmc_fdb_entry *hmc_fdb_insert(const u8 *addr, u16 iface_id)
{
	struct hmc_fdb_entry *fdb;

	HMC_TRACE();

	spin_lock_bh(&hmc->hash_lock);

	fdb = fdb_insert(addr, iface_id);

	spin_unlock_bh(&hmc->hash_lock);
	return fdb;
}

struct hmc_fdb_entry *hmc_fdb_lookup(const u8 *addr, u16 iface_id)
{
	struct hlist_head *head = &hmc->hash[hmc_mac_hash(addr, iface_id)];
	struct hmc_fdb_entry *fdb;

	spin_lock_bh(&hmc->hash_lock);

	fdb = fdb_find(head, addr, iface_id);

	spin_unlock_bh(&hmc->hash_lock);

	return fdb;
}

struct hmc_fdb_entry *hmc_fdb_lookup_best(const u8 *addr)
{
	int i;
	struct hmc_fdb_entry *f = NULL, *plc = NULL, *wlan = NULL;

	for (i = 0; i < HMC_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, &hmc->hash[i], hlist) {
			if (!is_valid_ether_addr(f->addr) || is_zero_ether_addr(f->addr))
				continue;

			if (ether_addr_equal(f->addr, addr)) {
				if (f->iface_id == HMC_PORT_PLC)
					plc = f;
				else if (f->iface_id == HMC_PORT_WIFI)
					wlan = f;
			}
		}
	}
	
	//hmc_dbg("dst = %pM, p = %p, w = %p\n", addr, plc, wlan);

	if (!plc && !wlan)
		return NULL;
	else if (!plc)
		return wlan;
	else if (!wlan)
		return plc;
	else {
		hmc_dbg("pm = %d, wm = %d\n", plc->metric, wlan->metric);
		if (plc->metric <= wlan->metric)
			return plc;
		else
			return wlan;
	}
}

void hmc_wpath_update(u8 *dst, u32 metric, u32 sn, int flags, int id)
{
	struct hmc_fdb_entry *fdb;

	mutex_lock(&hmc->rx_mutex);

	fdb = hmc_fdb_insert(dst, id);
	if (CHECK_MEM(fdb)) {
		hmc_err("Failed to update hmc path\n");
		mutex_unlock(&hmc->rx_mutex);
		return;
	}

	hmc_dbg("update dst: %pM, id: %d, sn: %d, metric: %d, flags: %d\n",
			dst, id, sn, metric, flags);

	fdb->iface_id = id;
	fdb->sn = sn;
	fdb->metric = metric;
	fdb->flags = flags;
	fdb->exp_time = jiffies;

	/*if (fdb->flags & MESH_PATH_ACTIVE)
		fdb_flush_tx_pending(fdb);*/

	mutex_unlock(&hmc->rx_mutex);
}

void hmc_path_update(u8 *dst, u32 metric, u32 sn, int flags, int id)
{
	struct hmc_fdb_entry *fdb;

	mutex_lock(&hmc->rx_mutex);

	fdb = hmc_fdb_insert(dst, id);
	if (CHECK_MEM(fdb)) {
		hmc_err("Failed to update hmc path\n");
		mutex_unlock(&hmc->rx_mutex);
		return;
	}

	hmc_dbg("update dst: %pM, id: %d, sn: %d, metric: %d, flags: %d\n",
			dst, id, sn, metric, flags);

	fdb->iface_id = id;
	fdb->sn = sn;
	fdb->metric = metric;
	fdb->flags = flags;
	fdb->exp_time = jiffies;

	/*if (fdb->flags & MESH_PATH_ACTIVE)
		fdb_flush_tx_pending(fdb);*/

	mutex_unlock(&hmc->rx_mutex);
}

int hmc_wpath_convert_proxy_to_dest(const u8 *proxy, u8 *dst)
{
	int ret = -1;
	struct mesh_path *mpath;
	struct hlist_node *n;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);
	struct mesh_table *tbl = sdata->u.mesh.mpp_paths;
	bool spin_lock = spin_is_locked(&tbl->walk_lock);

	hmc_dbg("convert proxy addr : %pM, lock = %d\n", proxy, spin_lock);

	if (!spin_lock)
		spin_lock_bh(&tbl->walk_lock);

	hlist_for_each_entry_safe(mpath, n, &tbl->walk_head, walk_list) {
		if (ether_addr_equal(mpath->mpp, proxy) &&
					is_valid_ether_addr(mpath->dst)) {
			memcpy(dst, mpath->dst, ETH_ALEN);
			ret = 0;
			goto out;
		}
	}

out:
	if (!spin_lock)
		spin_unlock_bh(&tbl->walk_lock);

	return ret;
}

struct mesh_path *hmc_wpath_mpp_lookup(const u8 *dst)
{
	struct mesh_path *mpath;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);

	rcu_read_lock();

	mpath = mpp_path_lookup(sdata, dst);
	if (!mpath) {
		hmc_err("mesh path is not found\n");
		rcu_read_unlock();
		return NULL;
	}

	rcu_read_unlock();

	return mpath;
}

struct mesh_path *hmc_wpath_lookup(const u8 *dst)
{
	struct mesh_path *mpath;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);

	hmc_info("lookup wifi path : %pM", dst);

	rcu_read_lock();

	mpath = mesh_path_lookup(sdata, dst);
	if (!mpath) {
		hmc_err("mesh path is not found\n");
		rcu_read_unlock();
		return NULL;
	}

	rcu_read_unlock();

	return mpath;
}

struct mesh_path *hmc_wpath_add(const u8 *dst)
{
	struct mesh_path *mpath;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);

	hmc_info("add wifi path : %pM", dst);

	rcu_read_lock();

	mpath = mesh_path_add(sdata, dst);
	if (!mpath) {
		hmc_err("Failed to add wifi mesh path\n");
		rcu_read_unlock();
		return NULL;
	}

	rcu_read_unlock();

	return mpath;
}

struct ak60211_mesh_path *hmc_ppath_lookup(const u8 *dst)
{
	struct ak60211_mesh_path *ppath;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();

	hmc_info("lookup plc path : %pM", dst);

	rcu_read_lock();

	ppath = ak60211_mpath_lookup(pdata, dst);
	if (CHECK_MEM(ppath)) {
		hmc_err("mesh path is not found\n");
		rcu_read_unlock();
		return NULL;
	}

	rcu_read_unlock();
	return ppath;
}

static void hmc_tx_skb_queue(struct hmc_fdb_entry *fdb, struct sk_buff *skb)
{
	struct sk_buff *skb_to_free = NULL;

	if (skb_queue_len(&fdb->frame_queue) >= HMC_SKB_QUEUE_LEN)
		skb_to_free = skb_dequeue(&fdb->frame_queue);

	skb_queue_tail(&fdb->frame_queue, skb);

	if (skb_to_free)
		fdb_discard_frame(skb_to_free);

	hmc_info("Tx frame was queued\n");
}

static int hmc_wlan_path_resolve(struct sk_buff *skb, u8 *addr)
{
	struct mesh_path *mmpath;
	struct mesh_path *mpath = NULL;
	struct sta_info *next_hop;
	struct hmc_fdb_entry *w_fdb;

	hmc_dbg("resolve addr : %pM", addr);

	w_fdb = hmc_fdb_insert(addr, HMC_PORT_WIFI);
	if (CHECK_MEM(w_fdb)) {
		hmc_err("Failed to insert dest addr to fdb (wifi), discard frames\n");
		fdb_discard_frame(skb);
		goto out;
	}

	mmpath = hmc_wpath_mpp_lookup(addr);
	if (mmpath) {
		mpath = hmc_wpath_lookup(mmpath->mpp);
		if (!mpath) {
			mpath = hmc_wpath_add(mmpath->mpp);
			if (CHECK_MEM(mpath)) {
				hmc_err("Unable to resolve wifi mesh path\n");
				goto out;
			}
			hmc_info("Try to resolve wifi mesh path\n");
			goto queue;
		}

		if (!(mpath->flags & MESH_PATH_ACTIVE)) {
			hmc_info("wifi path isn't active ... try to resolve\n");
			goto queue;
		}

		next_hop = rcu_dereference(mpath->next_hop);
		if (next_hop) {
			hmc_info("next_hop is found, update hmc tbl\n");
			hmc_path_update(addr, mpath->metric, mpath->sn, mpath->flags, HMC_PORT_WIFI);
			goto out;
		} else {
			hmc_info("waiting for wifi mesh healing itself ...\n");
			hmc_tx_skb_queue(w_fdb, skb);
			return NF_QUEUE;
		}
	}

queue:
	hmc_tx_skb_queue(w_fdb, skb);

	if (mpath != NULL)
		mesh_queue_preq(mpath, PREQ_Q_F_START | PREQ_Q_F_REFRESH);

	return NF_QUEUE;

out:
	return NF_ACCEPT;
}

static int hmc_plc_path_resolve(struct sk_buff *skb, u8 *addr)
{
	struct ak60211_mesh_path *ppath;
	struct hmc_fdb_entry *p_fdb;

	hmc_dbg("resolve addr : %pM", addr);

	p_fdb = hmc_fdb_insert(addr, HMC_PORT_PLC);
	if (CHECK_MEM(p_fdb)) {
		hmc_err("Failed to insert dest addr to fdb (wifi), discard frames\n");
		fdb_discard_frame(skb);
		return NF_ACCEPT;
	}

	ppath = hmc_ppath_lookup(addr);
	if (ppath) {
		if (ppath->flags & MESH_PATH_ACTIVE) {
			hmc_info("plc next hop is found, update hmc tbl");
			hmc_path_update(addr, ppath->metric, ppath->sn, ppath->flags, HMC_PORT_PLC);
			return NF_ACCEPT;
		}
	}

	hmc_info("Try to resolve plc mesh path\n");
	plc_hmc_preq_queue(addr);
	hmc_tx_skb_queue(p_fdb, skb);
	return NF_ACCEPT;
}

int hmc_xmit(struct sk_buff *skb, int egress)
{
	struct net_bridge *br;
	struct net_bridge_port *p, *n;

	if (CHECK_MEM(skb))
		return -ENOMEM;

	br = netdev_priv(hmc->bdev);

	mutex_lock(&hmc->xmit_mutex);
	rcu_read_lock();

	list_for_each_entry_safe(p, n, &br->port_list, list) {
		if (egress == HMC_PORT_FLOOD ||
			(egress == HMC_PORT_PLC && (strncmp(p->dev->name, "eth0", strlen("eth0")) == 0)) ||
			(egress == HMC_PORT_WIFI &&(strncmp(p->dev->name, "mesh0", strlen("mesh0")) == 0))) {
			hmc_dbg("forward to %s\n", p->dev->name);
			//hmc_print_skb(skb, "hmc_xmit");
			skb->dev = p->dev;
			dev_queue_xmit(skb);
		}
	}

	rcu_read_unlock();
	mutex_unlock(&hmc->xmit_mutex);
	return 0;
}

int hmc_br_tx_handler(struct sk_buff *skb)
{
	struct hmc_fdb_entry *fdb;
	u8 dest[ETH_ALEN] = {0};

	skb_reset_mac_header(skb);

	//hmc_print_skb(skb, "hmc_br_tx_handler");

	memcpy(dest, skb->data, ETH_ALEN);

	hmc_dbg("tx dst: %pM\n", dest);

	if (!is_valid_ether_addr(dest))
		return NF_DROP;

	/* If the dest can't be found in hmc tbl, it will be resolved later. */
	fdb = hmc_fdb_lookup_best(dest);
	if (fdb) {
		hmc_dbg("xmit dst: %pM, id: %d, metric: %d, sn: %d, flags: %d, active: %d\n",
				 fdb->addr, fdb->iface_id, fdb->metric,
				 fdb->sn, fdb->flags, (fdb->flags & MESH_PATH_ACTIVE));

		/* TODO: how does hmc recover by itself if tx is queued? */
		//if (fdb_expired(fdb))
		//	goto resolve;

		if (fdb->flags & MESH_PATH_ACTIVE) {
			if (fdb->iface_id == HMC_PORT_PLC && EN_PLC_ENCAP)
				ak60211_nexthop_resolved(skb, fdb->iface_id);
			else
				hmc_xmit(skb, fdb->iface_id);

			return NF_ACCEPT;
		}
	}

//resolve:

	hmc_plc_path_resolve(skb, dest);

	hmc_wlan_path_resolve(skb, dest);

	return NF_ACCEPT;
}

int hmc_br_rx_handler(struct sk_buff *skb)
{
	int ret;
	struct sk_buff *nskb = NULL;
	unsigned char *source = eth_hdr(skb)->h_source;

	if (ether_addr_equal(source, hmc->br_addr))
		return 1;

	//hmc_print_skb(skb, "hmc_rx_handler");

	//mutex_lock(&hmc->rx_mutex);

	/* SNAP data might be inside 802.3 frames even if coming from wifi egress. */
	ret = plc_hmc_rx(skb, nskb);

	//mutex_unlock(&hmc->rx_mutex);

	/* return to br_handle_frame */
	if (ret == NF_DROP)
		return 0;

	return 1;
}

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

static int __init hmc_core_init(void)
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

	ret = hmc_ops_init(hmc);
	if (ret < 0) {
		hmc_err("Failed to register hmc ops\n");
		goto err;
	}

	return 0;

err:
	hmc_dev_release();
	return ret;
}

static void __exit hmc_core_exit(void)
{
	hmc_info("hybrid mesh core exit\n");

	RCU_INIT_POINTER(br_should_route_hook, NULL);

	RCU_INIT_POINTER(nf_br_ops, NULL);

	if (hmc != NULL) {
		hmc_ops_deinit(hmc);

		if (hmc->bdev)
			dev_put(hmc->bdev);

		if (hmc->edev)
			dev_put(hmc->edev);

		if (hmc->wdev)
			dev_put(hmc->wdev);

		kfree(hmc);
		hmc = NULL;
	}

	hmc_misc_exit();

	hmc_fdb_fini();
}

module_init(hmc_core_init);
module_exit(hmc_core_exit);
MODULE_AUTHOR("AkiraNET");
MODULE_DESCRIPTION("Hybrid mesh experiment");
MODULE_LICENSE("GPL");