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

#include "hmc.h"

void hmc_ops_wifi_path_del(u8 *proxy)
{
	int i = 0;
	struct hmc_fdb_entry *f;
	struct hmc_core *hmc = to_get_hmc();

	hmc_dbg("delete proxy addr : %pM", proxy);

	rcu_read_lock();

	for (i = 0; i < HMC_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, &hmc->hash[i], hlist) {
			if (!is_valid_ether_addr(f->proxy) || is_zero_ether_addr(f->proxy))
				continue;

			if (ether_addr_equal(f->proxy, proxy) &&
				(f->iface_id == HMC_PORT_WIFI))  {
				hmc_info("DA and Pxoxy addr are matched (%pM ---> %pM)", f->proxy, f->addr);
				hmc_fdb_del(f->addr, HMC_PORT_WIFI);
				rcu_read_unlock();
				return;
			}
		}
	}

	hmc_err("Can't find wifi mesh addr (%pM) from hmc tbl", proxy);
	rcu_read_unlock();
}

void hmc_ops_wifi_path_update(u8 *proxy, u32 metric, u32 sn, int flags)
{
	int i = 0;
	struct hmc_fdb_entry *f;
	struct hmc_core *hmc = to_get_hmc();

	hmc_dbg("update wifi mesh addr (%pM)", proxy);

	for (i = 0; i < HMC_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, &hmc->hash[i], hlist) {
			if (!is_valid_ether_addr(f->proxy) || is_zero_ether_addr(f->proxy))
				continue;

			if (ether_addr_equal(f->proxy, proxy) &&
				(f->iface_id == HMC_PORT_WIFI))  {
				hmc_info("DA and Pxoxy addr are matched (%pM ---> %pM)", f->proxy, f->addr);
				hmc_path_update(f->addr, f->proxy, metric, sn, flags, HMC_PORT_WIFI);
				return;
			}
		}
	}

	hmc_err("Can't find wifi mesh addr (%pM) from hmc tbl", proxy);
}

void hmc_ops_plc_path_del(u8 *dst)
{
	hmc_dbg("delete dest addr : %pM", dst);

	rcu_read_lock();

	if (hmc_fdb_del(dst, HMC_PORT_PLC) < 0)
		hmc_err("delete %pM error in hmc tbl", dst);

	rcu_read_unlock();
}

void hmc_ops_plc_path_update(u8 *dst, u32 metric, u32 sn, int flags, int id)
{
	hmc_dbg("update plc dest addr: %pM\n", dst);
	hmc_path_update(dst, dst, metric, sn, flags, HMC_PORT_PLC);
}

int hmc_ops_fdb_dump(struct nl60211_mesh_info *info, int size)
{
	int i = 0, idx = 0;
	struct hmc_fdb_entry *f;
	struct hmc_core *hmc = to_get_hmc();

	HMC_TRACE();

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
				memcpy(info[idx].proxy, f->proxy, ETH_ALEN);
				info[idx].metric = f->metric;
				info[idx].sn = f->sn;
				info[idx].flags = f->flags;
				info[idx].iface_id = f->iface_id;
				idx++;
			}
		}
	}

	return 0;
}


int hmc_ops_fdb_lookup(struct hmc_fdb_entry *f, const u8 *addr, u16 id)
{
	struct hmc_fdb_entry *tmp;

	HMC_TRACE();

	tmp = hmc_fdb_lookup(addr, id);

	if (!tmp)
		return -ENOMEM;
	
	memcpy(f->addr, tmp->addr, ETH_ALEN);
	f->sn = tmp->sn;
	f->flags = tmp->flags;
	f->metric = tmp->metric;
	f->iface_id = tmp->iface_id;
	f->exp_time = tmp->exp_time;
	return 0;
}

int hmc_ops_fdb_insert(const u8 *addr, u16 id)
{
	struct hmc_fdb_entry *tmp;

	HMC_TRACE();

	tmp = hmc_fdb_insert(addr, id);
	return (!tmp) ? -ENOMEM : 0;
}

int hmc_ops_xmit(struct sk_buff *skb, int egress)
{
	hmc_dbg("xmit = (%d, %s)\n", egress, (egress == HMC_PORT_PLC) ? "PLC" : "WIFI");

	return hmc_xmit(skb, egress);
}

int hmc_ops_fdb_del(const u8 *addr, u16 id)
{
	HMC_TRACE();

	if (!is_valid_ether_addr(addr))
		return -EINVAL;

	return hmc_fdb_del(addr, id);
}

static const struct mac80211_hmc_ops mac_hmc_ops = {
	.path_update = hmc_ops_wifi_path_update,
	.path_del = hmc_ops_wifi_path_del,
};

static const struct ak60211_hmc_ops ak_hmc_ops = {
	.path_update = hmc_ops_plc_path_update,
	.path_del = hmc_ops_plc_path_del,
	.xmit = hmc_ops_xmit,
	.fdb_insert = hmc_ops_fdb_insert,
	.fdb_del = hmc_ops_fdb_del,
	.fdb_dump = hmc_ops_fdb_dump,
	.fdb_lookup = hmc_ops_fdb_lookup,
};

static int hmc_ops_mac_register(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	return ieee80211_mesh_hmc_ops_register(sdata, &mac_hmc_ops);
}

static int hmc_ops_ak_register(void)
{
	return ak60211_mesh_hmc_ops_register(&ak_hmc_ops);
}

static void hmc_ops_mac_unregister(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	ieee80211_mesh_hmc_ops_unregister(sdata);
}

static void hmc_ops_ak_unregister(void)
{
	ak60211_mesh_hmc_ops_unregister();
}

int hmc_ops_init(struct hmc_core *hmc)
{
	hmc_info("hybrid mesh ops init\n");

	if (hmc_ops_mac_register(hmc->wdev))
		return -ENODEV;

	if (hmc_ops_ak_register() < 0)
		return -ENODEV;

	return 0;
}

void hmc_ops_deinit(struct hmc_core *hmc)
{
	hmc_info("hybrid mesh ops deinit\n");

	hmc_ops_mac_unregister(hmc->wdev);
	hmc_ops_ak_unregister();
}
