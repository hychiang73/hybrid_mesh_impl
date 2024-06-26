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

static int hmc_wlan_path_resolve(struct sk_buff *skb, u8 *addr);
static int hmc_plc_path_resolve(struct sk_buff *skb, u8 *addr);
static void hmc_tx_skb_queue(struct sk_buff *skb);

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

int hmc_check_port_state(int port)
{
	struct net_bridge_port *p;

	if (port == HMC_PORT_PLC)
		p = br_port_get_rtnl(hmc->edev);
	else
		p = br_port_get_rtnl(hmc->wdev);

	if (!p)
		return -ENODEV;

	if (p->state == BR_STATE_FORWARDING)
		return 0;
	else
		return -1;
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

static void fdb_flush_tx_pending(struct hmc_fdb_entry *fdb)
{
	struct sk_buff *skb;
	struct mesh_path *mppath = NULL;
	u8 da[ETH_ALEN] = {0};
	int egress = fdb->iface_id;

	while ((skb = skb_dequeue(&hmc->frame_queue)) != NULL) {
		if (egress == HMC_PORT_WIFI) {
			mppath = hmc_wpath_mpp_lookup(skb->data);
			if (mppath)
				memcpy(da, mppath->dst, ETH_ALEN);
		}

		if (!is_valid_ether_addr(da))
			memcpy(da, skb->data, ETH_ALEN);

		hmc_info("### dequeue skb addr : %pM, DA : %pM", skb->data, da);

		if (!ether_addr_equal(da, skb->data)) {
			hmc_info("discard queued skb");
			fdb_discard_frame(skb);
			continue;
		}

		hmc_info("### dequeue egress : %d", egress);

		if (egress == HMC_PORT_PLC && EN_PLC_ENCAP)
			ak60211_nexthop_resolved(skb, egress);
		else
			hmc_xmit(skb, egress);
	}
}

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
	struct hmc_fdb_entry *plc = NULL, *wlan = NULL;
	u8 wmac[ETH_ALEN] = {0};

	hmc_convert_da_to_wmac(addr, wmac);

	plc = hmc_fdb_lookup(addr, HMC_PORT_PLC);

	wlan = hmc_fdb_lookup(wmac, HMC_PORT_WIFI);

	if (!plc && !wlan)
		return NULL;
	else if (!plc)
		return wlan;
	else if (!wlan)
		return plc;
	else {
		hmc_dbg("pm = %d, wm = %d\n", plc->metric, wlan->metric);
		if (plc->metric <= wlan->metric) {
			if (hmc_check_port_state(HMC_PORT_PLC) != 0) {
				hmc_err("eth0 port is disabled ... switch to wlan0");
				return wlan;
			}
			return plc;
		}
		return wlan;
	}
}

int hmc_path_fwd(struct sk_buff *skb)
{
	struct hmc_fdb_entry *f;
	unsigned char *dest = eth_hdr(skb)->h_dest;

	if (skb->pkt_type != PACKET_OTHERHOST)
		return NF_DROP;

	if (!is_unicast_ether_addr(dest))
		return NF_DROP;

	f = hmc_fdb_lookup_best(dest);
	if (!f) {
		hmc_err("Can't find addr from hmc tbl, resolving ...");
		hmc_wlan_path_resolve(skb, dest);
		hmc_plc_path_resolve(skb, dest);
		return NF_DROP;
	}

	skb_push(skb, ETH_HLEN);
	hmc_info("## forward DA : %pM , SA : %pM", skb->data, skb->data + ETH_ALEN);
	hmc_xmit(skb, f->iface_id);

	return NF_ACCEPT;
}

void hmc_path_update(u8 *dst, u32 metric, u32 sn, int flags, int id)
{
	struct hmc_fdb_entry *fdb;

	fdb = hmc_fdb_insert(dst, id);
	if (CHECK_MEM(fdb)) {
		hmc_err("Failed to update hmc path\n");
		return;
	}

	hmc_dbg("update DA: %pM, id: %d, sn: %d, metric: %d, flags: %d\n",
			dst, id, sn, metric, flags);

	fdb->iface_id = id;
	fdb->sn = sn;
	fdb->metric = metric;
	fdb->flags = flags;
	fdb->exp_time = jiffies;

	if (fdb->flags & MESH_PATH_ACTIVE)
		fdb_flush_tx_pending(fdb);
}

int hmc_convert_da_to_wmac(const u8 *da, u8 *wmac)
{
	struct mesh_path *mpath = NULL;
	struct mesh_path *mppath = NULL;
	struct sta_info *next_hop = NULL;
	bool mpp_lookup = true;

	mpath = hmc_wpath_lookup(da);
	if (mpath) {
		mpp_lookup = false;
		next_hop = rcu_dereference(mpath->next_hop);
		if (!next_hop || !(mpath->flags & (MESH_PATH_ACTIVE | MESH_PATH_RESOLVING)))
			mpp_lookup = true;
	}

	if (mpp_lookup)
		mppath = hmc_wpath_mpp_lookup(da);

	if (mppath)
		memcpy(wmac, mppath->mpp, ETH_ALEN);
	else if (mpath)
		memcpy(wmac, mpath->dst, ETH_ALEN);
	else
		memcpy(wmac, da, ETH_ALEN);

	hmc_dbg("convert (%pM) --> (%pM)\n", da, wmac);
	return 0;
}

struct mesh_path *hmc_wpath_mpp_lookup(const u8 *dst)
{
	struct mesh_path *mpath;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(hmc->wdev);

	rcu_read_lock();

	mpath = mpp_path_lookup(sdata, dst);
	if (!mpath) {
	//	hmc_err("wifi mesh proxy path is not found\n");
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

	hmc_dbg("lookup wifi path : %pM", dst);

	rcu_read_lock();

	mpath = mesh_path_lookup(sdata, dst);
	if (!mpath) {
	//	hmc_err("wifi mesh path is not found\n");
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
		hmc_err("plc mesh path is not found\n");
		rcu_read_unlock();
		return NULL;
	}

	rcu_read_unlock();
	return ppath;
}

static void hmc_tx_skb_queue(struct sk_buff *skb)
{
	struct sk_buff *skb_to_free = NULL;
	unsigned long flags;

	spin_lock_irqsave(&hmc->queue_lock, flags);

	if (skb_queue_len(&hmc->frame_queue) >= HMC_SKB_QUEUE_LEN)
		skb_to_free = skb_dequeue(&hmc->frame_queue);

	skb_queue_tail(&hmc->frame_queue, skb);

	if (skb_to_free)
		fdb_discard_frame(skb_to_free);

	hmc_info("##### Tx frame (%p) was queued\n", skb);
	spin_unlock_irqrestore(&hmc->queue_lock, flags);
}

static int hmc_wlan_path_resolve(struct sk_buff *skb, u8 *addr)
{
	struct mesh_path *mmpath = NULL;
	struct mesh_path *mpath = NULL;
	u8 proxy[ETH_ALEN] = {0};

	hmc_dbg("resolve addr : %pM", addr);

	mpath = hmc_wpath_lookup(addr);
	if (!mpath) {
		mmpath = hmc_wpath_mpp_lookup(addr);
		if (mmpath)
			mpath = hmc_wpath_lookup(mmpath->mpp);
	}

	if (!mpath && !mmpath) {
		hmc_err("Cannot resolve wifi mesh path");
		return -ENOENT;
	}

	if (mpath) {
		memcpy(proxy, mpath->dst, ETH_ALEN);
	} else if (!mpath && mmpath) {
		hmc_err("Found proxy path but mesh path is empty");
		memcpy(proxy, mmpath->mpp, ETH_ALEN);
		mpath = hmc_wpath_add(mmpath->mpp);
	}

	hmc_path_update(proxy, mpath->metric, mpath->sn, mpath->flags, HMC_PORT_WIFI);

	if (!(mpath->flags & MESH_PATH_RESOLVING)) {
		hmc_err("call wifi PREQ queue");
		mesh_queue_preq(mpath, PREQ_Q_F_START | PREQ_Q_F_REFRESH);
	}

	return NF_QUEUE;
}

static int hmc_plc_path_resolve(struct sk_buff *skb, u8 *addr)
{
	struct ak60211_mesh_path *ppath;

	hmc_dbg("resolve addr : %pM", addr);

	if (hmc_check_port_state(HMC_PORT_PLC) != 0)
		return -ENODEV;

	ppath = hmc_ppath_lookup(addr);
	if (!ppath) {
		plc_hmc_preq_queue(addr);
		return NF_QUEUE;
	}

	hmc_path_update(addr, ppath->metric, ppath->sn, ppath->flags, HMC_PORT_PLC);

	if (!(ppath->flags & MESH_PATH_RESOLVING)) {
		hmc_err("call plc PREQ queue");
		plc_hmc_preq_queue(addr);
	}

	return NF_QUEUE;
}

int hmc_xmit(struct sk_buff *skb, int egress)
{
	struct net_bridge *br = netdev_priv(hmc->bdev);
	struct net_bridge_port *p, *n;
	struct hmc_fdb_entry *fdb;
	u8 dest[ETH_ALEN] = {0};

	if (CHECK_MEM(skb))
		return -ENOMEM;

	if (egress == HMC_PORT_BEST) {
		memcpy(dest, skb->data, ETH_ALEN);
		fdb = hmc_fdb_lookup_best(dest);
		if (!CHECK_MEM(fdb)) {
			hmc_dbg("best xmit port : %d", fdb->iface_id);
			if (fdb->iface_id == HMC_PORT_PLC) {
				skb->dev = hmc->edev;
				dev_queue_xmit(skb);
			} else {
				skb->dev = hmc->wdev;
				dev_queue_xmit(skb);
			}
		}
		return 0;
	}

	list_for_each_entry_safe(p, n, &br->port_list, list) {
		if (egress == HMC_PORT_FLOOD ||
			(egress == HMC_PORT_PLC && (strncmp(p->dev->name, "eth0", strlen("eth0")) == 0)) ||
			(egress == HMC_PORT_WIFI &&(strncmp(p->dev->name, "mesh0", strlen("mesh0")) == 0))) {
			hmc_dbg("xmit port : %s\n", p->dev->name);
			//hmc_print_skb(skb, "hmc_xmit");
			skb->dev = p->dev;
			dev_queue_xmit(skb);
		}
	}

	return 0;
}

int hmc_br_tx_handler(struct sk_buff *skb)
{
	struct hmc_fdb_entry *fdb;
	u8 dest[ETH_ALEN] = {0};

	skb_reset_mac_header(skb);

	memcpy(dest, skb->data, ETH_ALEN);

	if (!is_valid_ether_addr(dest))
		return NF_DROP;

	fdb = hmc_fdb_lookup_best(dest);
	if (!fdb)
		goto queue;

	hmc_dbg("xmit dst: %pM, id: %d, metric: %d, sn: %d, flags: %d, active: %d\n",
			fdb->addr, fdb->iface_id, fdb->metric,
			fdb->sn, fdb->flags, (fdb->flags & MESH_PATH_ACTIVE));

	if (fdb->flags & MESH_PATH_ACTIVE) {
		if (fdb->iface_id == HMC_PORT_PLC && EN_PLC_ENCAP) {
			if (ak60211_nexthop_resolved(skb, fdb->iface_id) == NF_DROP)
				goto queue;
		} else
			hmc_xmit(skb, fdb->iface_id);

		return NF_ACCEPT;
	}

queue:
	hmc_tx_skb_queue(skb);
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

	//hmc_dbg("received from %s", skb->dev->name);
	//hmc_print_skb(skb, "hmc_rx_handler");

	/* SNAP data might be inside 802.3 frames even if coming from wifi egress. */
	ret = plc_hmc_rx(skb, nskb);

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

	hmc_info("hybrid mesh core version %s\n", HMC_VERSION);

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
	spin_lock_init(&hmc->queue_lock);
	skb_queue_head_init(&hmc->frame_queue);
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
