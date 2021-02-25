
#ifndef _HMC_H
#define _HMC_H

#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/netpoll.h>
#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>

#include "mac60211.h"
#include "ak60211_mesh_private.h"
#include "../mac80211/mesh.h"
#include "../bridge/br_private.h"

#define HMC_SKB_QUEUE_LEN		5
#define HMC_HASH_BITS			8
#define HMC_MAX_NODES			16
#define HMC_DEF_EXP_TIME		(10 * HZ)
#define HMC_HASH_SIZE			(1 << HMC_HASH_BITS)
#define CHECK_MEM(X)			((IS_ERR(X) || X == NULL) ? 1 : 0)

#define hmc_info(fmt, arg...)										\
({																	\
    pr_info("HMC: (%s, %d): " fmt, __func__, __LINE__, ##arg);		\
})																	\

#define hmc_err(fmt, arg...)										\
({																	\
    pr_err("HMC: (%s, %d): " fmt, __func__, __LINE__, ##arg);		\
})																	\

#define HMC_TRACE()	pr_info("HMC: (%s, %d): ", __func__, __LINE__);

/* debug */
extern bool hmc_debug;
#define hmc_dbg(fmt, arg...)										\
do {																\
	if (hmc_debug)													\
	pr_info("HMC: (%s, %d): " fmt, __func__, __LINE__, ##arg);		\
} while (0)

enum hmc_port_egress {
	HMC_PORT_FLOOD = 0,
	HMC_PORT_PLC,
	HMC_PORT_WIFI,
	HMC_PORT_BEST,
	HMC_PORT_NONE = 0xFF
};

struct nl60211_mesh_info
{
	u8 dst[ETH_ALEN];
	u16 iface_id;
	u32 sn;
	u32 metric;
	enum mesh_path_flags flags;
};

struct hmc_fdb_entry {
	struct hlist_node hlist;
	struct sk_buff_head frame_queue;
	unsigned char addr[ETH_ALEN];
	u16 iface_id;
	u32 sn;
	u32 metric;
	enum mesh_path_flags flags;
	unsigned long exp_time;
};

struct hmc_core {
	unsigned char br_addr[ETH_ALEN];

	spinlock_t hash_lock;
	struct hlist_head hash[HMC_HASH_SIZE];

	struct net_device *bdev;
	struct net_device *edev;
	struct net_device *wdev;

	struct mutex rx_mutex;
	struct mutex xmit_mutex;

	unsigned long aging_time;
};

/* core.c */
struct mesh_path *hmc_wpath_lookup(const u8 *addr);
struct ak60211_mesh_path *hmc_ppath_lookup(const u8 *addr);

struct hmc_fdb_entry *hmc_fdb_insert(const u8 *addr, u16 iface_id);
struct hmc_fdb_entry *hmc_fdb_lookup(const u8 *addr, u16 iface_id);
struct hmc_fdb_entry *hmc_fdb_lookup_best(const u8 *addr);
int hmc_fdb_dump(struct nl60211_mesh_info *info, int size);
int hmc_fdb_del(const u8 *addr, u16 iface_id);

struct hmc_core *hmc_to_core(void);
int hmc_get_dev_addr(u8 *addr);
int hmc_xmit(struct sk_buff *skb, enum hmc_port_egress egress);

int hmc_core_init(void);
void hmc_core_exit(void);

/* misc.c */
void hmc_print_skb(struct sk_buff *skb, const char *type);
int hmc_misc_init(void);
void hmc_misc_exit(void);

/* ak60211 function */
void ak60211_nexthop_resolved(struct sk_buff *skb, u8 iface_id);

#endif /* _HMC_H */
