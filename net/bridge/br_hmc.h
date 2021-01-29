/*
 *	Bridge with hybrid mesh core
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_HMC_H
#define _BR_HMC_H

#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/netpoll.h>
#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>

#define HMC_PLC_ID				0
#define HMC_WIFI_ID				1
#define HMC_NL_ID				2
#define HMC_FRAME_QUEUE_LEN 	5
#define HMC_MAX_NODES			32
#define CHECK_MEM(X)			((IS_ERR(X) || X == NULL) ? 1 : 0)

#define br_hmc_info(fmt, arg...)									\
({																	\
    pr_info("BR-HMC: (%s, %d): " fmt, __func__, __LINE__, ##arg);	\
})																	\

#define br_hmc_err(fmt, arg...)										\
({																	\
    pr_err("BR-HMC: (%s, %d): " fmt, __func__, __LINE__, ##arg);	\
})																	\

/* debug */
extern bool br_hmc_debug;
#define BR_TRACE()													\
do {																\
	if (br_hmc_debug)												\
	br_hmc_info("%s\n", __func__);										\
} while (0)

#define br_hmc_dbg(fmt, arg...)										\
do {																\
	if (br_hmc_debug)												\
	pr_info("BR-HMC: (%s, %d): " fmt, __func__, __LINE__, ##arg);	\
} while (0)

enum br_hmc_path_flags {
	BR_HMC_PATH_ACTIVE =		BIT(0),
	BR_HMC_PATH_RESOLVING =		BIT(1),
	BR_HMC_PATH_SN_VALID =		BIT(2),
	BR_HMC_PATH_FIXED	=		BIT(3),
	BR_HMC_PATH_RESOLVED =		BIT(4),
	BR_HMC_PATH_REQ_QUEUED =	BIT(5),
	BR_HMC_PATH_DELETED =		BIT(6),
	BR_HMC_PATH_INVALID =		BIT(7),
};

enum hmc_br_cmd {
	HMC_ADD_BR = 0x100,
	HMC_ADD_IF = 0x101,
};

enum hmc_port_egress {
	HMC_PORT_FLOOD = 0,
	HMC_PORT_PLC,
	HMC_PORT_WIFI,
	HMC_PORT_BEST,
	HMC_PORT_NONE = 0xFF
};

struct hmc_hybrid_path
{
	u8 dst[ETH_ALEN];
	u32 sn;
	u32 metric;
	enum br_hmc_path_flags flags;
};

struct nl60211_mesh_info
{
	u8 dst[ETH_ALEN];
	u32 metric;
	u32 sn;
	enum br_hmc_path_flags flags;
	enum hmc_port_egress egress;
};

struct hmc_path {
	u8 dst[ETH_ALEN];
	struct rhash_head rhash;
	struct hlist_node walk_list;
	struct sk_buff_head frame_queue;
	u32 sn;
	u32 metric;
	enum br_hmc_path_flags flags;
	enum hmc_port_egress egress;
};

struct hmc_table {
	struct rhashtable rhead;
	struct hlist_head walk_head;
	spinlock_t walk_lock;
	atomic_t entries;
};

struct net_bridge_hmc
{
	u8 id;
	unsigned char br_addr[ETH_ALEN];
	struct net_bridge_hmc_ops *ops;
	struct hmc_hybrid_path *path;
	enum hmc_port_egress egress;

	struct list_head list;
};

struct net_bridge_hmc_ops
{
	int (*rx)(struct sk_buff *skb);
	void (*queue_preq)(struct net_bridge_hmc *port);
};

/* br_hmc.c */
struct hmc_path *br_hmc_path_add(const u8 *dst);
struct hmc_path *br_hmc_path_lookup(const u8 *dst);
struct net_bridge_hmc *br_hmc_port_lookup(u8 port);
struct net_bridge_hmc *br_hmc_alloc(const char *name, struct net_bridge_hmc_ops *ops);
int br_hmc_path_lookup_by_idx(struct nl60211_mesh_info *info, int idx);
int br_hmc_path_update(struct net_bridge_hmc *hmc);
int br_hmc_path_del(const u8 *addr);
int br_hmc_forward(struct sk_buff *skb, struct net_bridge_hmc *hmc);
void br_hmc_notify(int cmd, struct net_device *dev);
int br_hmc_init(void);
void br_hmc_deinit(void);

/* br_hmc_misc.c */
int br_hmc_misc_init(void);
void br_hmc_misc_exit(void);
void br_hmc_print_skb(struct sk_buff *skb, const char *type, int offset);

#endif /* _BR_HMC_H */
