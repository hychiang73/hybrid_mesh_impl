#ifndef AK60211_MESH_PRIVATE_H
#define AK60211_MESH_PRIVATE_H

#include <net/arp.h>
#include <net/ip.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netpoll.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <net/dsa.h>
#include <net/sock.h>
#include <linux/if_vlan.h>
#include <net/switchdev.h>
#include <net/net_namespace.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/netfilter_bridge.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/ieee80211.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>

#include "../hmc/hmc.h"
#include "mac60211.h"

#define plc_debug(fmt, arg...)							\
({										\
	if (plc_dbg)								\
		pr_info("PLC: (%s, %d): " fmt, __func__, __LINE__, ##arg);	\
})										\

#define plc_info(fmt, arg...)							\
({										\
	pr_info("PLC: (%s, %d): " fmt, __func__, __LINE__, ##arg);		\
})										\

#define plc_err(fmt, arg...)							\
({										\
	pr_err("PLC: (%s, %d): " fmt, __func__, __LINE__, ##arg);		\
})										\

#define PLC_TRACE()		plc_debug("%s\n", __func__);

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define MAX_PREQ_QUEUE_LEN	64
#define SBEACON_DELAY		5000
#define AK60211_MESH_HWMP_PATH_TIMEOUT	3000
#define MAX_MESH_TTL	31
#define MESH_TRAVERSAL_TIME  50
#define PLC_MESH_MAX_PLINKS		16
#define MESH_MAX_PATHS	   1024
#define MAX_METRIC	0xffffffff
#define MSEC_TO_TU(x) ((x) * 1000 / 1024)
#define SN_GT(x, y) ((s32)((y) - (x)) < 0)
#define SN_LT(x, y) ((s32)((x) - (y)) < 0)
#define MAX_SANE_SN_DELTA 32

/* Housekeeping timer 5s */
#define AK60211_MESH_HOUSEKEEPING_INTERVAL	(5 * HZ)
#define MESH_PATH_EXPIRE	(600 * HZ)

#define AK60211_FCTL_FTYPE			0x000c
#define AK60211_FCTL_STYPE			0x00f0
#define AK60211_FCTL_TODS			0x0100
#define AK60211_FCTL_FROMDS			0x0200

#define AK60211_FTYPE_MGMT			0x0000	 // 0b00
#define AK60211_FTYPE_CTRL			0x0004	 // 0b01
#define AK60211_FTYPE_DATA			0x0008	 // 0b10

/* management */
#define AK60211_STYPE_BEACON		0x0080	 // 0b1000
#define AK60211_STYPE_PROBE_REQ		0x0040	 // 0b0100
#define AK60211_STYPE_PROBE_RESP	0x0050	 // 0b0101
#define AK60211_STYPE_ACTION		0x00D0	 // 0b1101

/* data */
#define AK60211_STYPE_QOSDATA		0x0080	 // 0b1000

/* Mesh flags */
#define PLC_MESH_FLAGS_AE_A4 	0x1
#define PLC_MESH_FLAGS_AE_A5_A6	0x2
#define PLC_MESH_FLAGS_AE		0x3
#define PLC_MESH_FLAGS_PS_DEEP	0x4

enum ak60211_plink_event {
	PLINK_UNDEFINED,
	OPN_ACPT,
	OPN_RJCT,
	OPN_IGNR,
	CNF_ACPT,
	CNF_RJCT,
	CNF_IGNR,
	CLS_ACPT,
	CLS_IGNR
};

enum ak60211_plink_state {
	AK60211_PLINK_LISTEN,
	AK60211_PLINK_OPN_SNT,
	AK60211_PLINK_OPN_RCVD,
	AK60211_PLINK_CNF_RCVD,
	AK60211_PLINK_ESTAB,
	AK60211_PLINK_HOLDING,
	AK60211_PLINK_BLOCKED,

	/* keep last */
	NUM_AK60211_PLINK_STATES,
	MAX_AK60211_PLINK_STATES = NUM_AK60211_PLINK_STATES - 1
};

enum ak60211_mpath_frame_type {
	AK60211_MPATH_PREQ = 0,
	AK60211_MPATH_PREP,
	AK60211_MPATH_PERR,
	AK60211_MPATH_RANN
};

enum ak60211_mpath_flags {
	PLC_MESH_PATH_ACTIVE = BIT(0),
	PLC_MESH_PATH_RESOLVING = BIT(1),
	PLC_MESH_PATH_SN_VALID = BIT(2),
	PLC_MESH_PATH_FIXED = BIT(3),
	PLC_MESH_PATH_RESOLVED = BIT(4),
	PLC_MESH_PATH_REQ_QUEUED = BIT(5),
	PLC_MESH_PATH_DELETED = BIT(6),
};

/* Self Protected Action codes */
enum ak60211_sp_actioncode {
	AK60211_SP_RESERVED = 0,
	AK60211_SP_MESH_PEERING_OPEN = 1,
	AK60211_SP_MESH_PEERING_CONFIRM = 2,
	AK60211_SP_MESH_PEERING_CLOSE = 3,
	AK60211_SP_MGK_INFORM = 4,
	AK60211_SP_MGK_ACK = 5,
};

enum ak60211_mesh_task_flags {
	AK60211_MESH_WORK_HOUSEKEEPING,
};

static const char * const mplstates[] = {
	[AK60211_PLINK_LISTEN] = "LISTEN",
	[AK60211_PLINK_OPN_SNT] = "OPN-SNT",
	[AK60211_PLINK_OPN_RCVD] = "OPN-RCVD",
	[AK60211_PLINK_CNF_RCVD] = "CNF_RCVD",
	[AK60211_PLINK_ESTAB] = "ESTAB",
	[AK60211_PLINK_HOLDING] = "HOLDING",
	[AK60211_PLINK_BLOCKED] = "BLOCKED"
};

static const char * const mplevents[] = {
	[PLINK_UNDEFINED] = "NONE",
	[OPN_ACPT] = "OPN_ACPT",
	[OPN_RJCT] = "OPN_RJCT",
	[OPN_IGNR] = "OPN_IGNR",
	[CNF_ACPT] = "CNF_ACPT",
	[CNF_RJCT] = "CNF_RJCT",
	[CNF_IGNR] = "CNF_IGNR",
	[CLS_ACPT] = "CLS_ACPT",
	[CLS_IGNR] = "CLS_IGNR"
};


struct ak60211_mesh_table {
	struct rhashtable	rhead;
	struct hlist_head	walk_head;
	/* mesh table walk spinlock  */
	spinlock_t	walk_lock;
	atomic_t	entries;
};

struct ak60211_mesh_config {
	u16 MeshRetryTimeout;
	u16 MeshConfirmTimeout;
	u16 MeshHoldingTimeout;
	u16 MeshMaxPeerLinks;
	u8 MeshMaxRetries;
	u8 MeshTTL;
	u8 element_ttl;
	u8 MeshHWMPmaxPREQretries;
	u32 path_refresh_time;
	u16 min_discovery_timeout;
	u32 MeshHWMPactivePathTimeout;
	u16 MeshHWMPpreqMinInterval;
	u16 MeshHWMPperrMinInterval;
	u16 MeshHWMPnetDiameterTraversalTime;
	s32 rssi_threshold;
	u32 plink_timeout;
	u16 beacon_interval;
};

#define AK60211_PREQ_START		0x01
#define AK60211_PREQ_REFRESH	0x02

#define MAX_MESH_ID_LEN			32

struct ak60211_mesh_preq_queue {
	struct list_head list;
	u8 dst[ETH_ALEN];
	u8 flags;
};

struct ak60211_sta_info {
	struct rhlist_head hash_node;
	struct list_head list;
	struct rcu_head rcu_head;
	struct ak60211_if_data	*local;

	struct timer_list			plink_timer;
	enum ak60211_plink_state	plink_state;
	/* sta peerlink spinlock */
	spinlock_t plink_lock;
	u8	plink_retries;
	u32	plink_timeout;
	u32	ewma_fail_avg;
	u16	llid;
	u16	plid;
	u16	reason;
	u16	processed_beacon:1, connected_to_gate:1, used:1;
	u16	retry:8, reserved:5;
	u8	addr[6];
};

struct hmc_fdb_entry;
struct nl60211_mesh_info;

/*
 * struct ak60211_hmc_ops - callback from ak60211 mesh to hybrid mesh core
 */
struct ak60211_hmc_ops {
	void (*path_update)(u8 *addr, u32 metric, u32 sn, int flags, int id);
	void (*path_del)(u8 *dst);
	int (*xmit)(struct sk_buff *skb, int egress);
	int (*xmit_cp)(struct sk_buff *skb);
	int (*fdb_insert)(const u8 *addr, u16 id);
	int (*fdb_lookup)(struct hmc_fdb_entry *f, const u8 *addr, u16 id);
	int (*fdb_del)(const u8 *addr, u16 id);
	int (*fdb_dump)(struct nl60211_mesh_info *info, int size);
};

struct ak60211_if_data {
	struct timer_list housekeeping_timer;
	struct timer_list mesh_path_timer;

	/* work & workqueue */
	struct work_struct work;
	struct workqueue_struct *workqueue;
	unsigned long wrkq_flags;

	u32 mgmt_sn;
	u32 action_sn;
	u32 sn;
	u32 preq_id;
	unsigned long last_sn_update;
	u32 mesh_seqnum;

	/* hmc ops */
	const struct ak60211_hmc_ops *hmc_ops;

	u8 addr[ETH_ALEN];
	u8 mesh_id[MAX_MESH_ID_LEN];
	size_t mesh_id_len;
	atomic_t mpaths;
	/* Timestamp of last PREQ sent */
	unsigned long last_preq;
	struct ak60211_mesh_config mshcfg;
	atomic_t estab_plinks;
	bool accepting_plinks;

	struct ak60211_mesh_table *mesh_paths;
	int mesh_paths_generations;

	/* mesh preq queue element */
	spinlock_t mesh_preq_queue_lock;
	struct ak60211_mesh_preq_queue preq_queue;
	int preq_queue_len;

	/* sta management */
	struct list_head sta_list;
	struct rhltable sta_hash;
	/* sta mutex */
	struct mutex sta_mtx;
	unsigned long num_sta;
	int sta_generation;

	/* iface mutex */
	struct mutex mtx;
};

struct ak60211_mesh_path {
	u8	dst[ETH_ALEN];
	struct rhash_head	rhash;
	struct hlist_node	walk_list;
	struct ak60211_if_data	*sdata;
	struct ak60211_sta_info __rcu *next_hop;
	struct timer_list timer;
	struct rcu_head rcu;
	u32 sn;
	u32 metric;
	u8 hop_count;
	unsigned long exp_time;
	u32 discovery_timeout;
	u8 discovery_retries;
	enum ak60211_mpath_flags flags;
	/* mesh path state change lock */
	spinlock_t state_lock;
	bool is_root;
};

struct meshidhdr {
	u8	   elemid;
	u8	   len;
	u8	   meshid[MAX_MESH_ID_LEN];
} __packed;

struct mesh_formation_info {
	u8	 connected_to_gate:1;
	u8	 num_of_peerings:6;
	u8	 connected_as:1;
} __packed;

struct mesh_capability {
	u8	 accepting_addi_mesh_peerings:1;
	u8	 mcca_sup:1;
	u8	 mcca_en:1;
	u8	 forwarding:1;
	u8	 mbca_en:1;
	u8	 tbtt_adjusting:1;
	u8	 ps:1;
	u8	 reserved:1;
} __packed;

struct meshconfhdr {
	u8	   elemid;
	u8	   len;
	u8	   psel_protocol;
	u8	   psel_metric;
	u8	   congestion_ctrl_mode;
	u8	   sync_method;
	u8	   auth_protocol;
	struct mesh_formation_info	mesh_formation;
	struct mesh_capability		mesh_cap;
} __packed;

struct meshprofhdr {
	struct meshidhdr	meshid_elem;
	struct meshconfhdr	meshconf_elem;
} __packed;

struct mpm_hdr {
	u8	  meshid_elem;
	u8	  len;
	u16   mesh_peer_protocol;
	u16   llid;
	u16   plid;
	u16   reason;
	u8	  pmk[16];
} __packed;

struct plc_hdr {
	__le16	   framectl;
	__le16	   duration_id;
	struct {
		u8	  h_addr1[ETH_ALEN];
		u8	  h_addr2[ETH_ALEN];
		u8	  h_addr3[ETH_ALEN];
		u8	  h_addr4[ETH_ALEN];
		u8	  h_addr5[ETH_ALEN];
		u8	  h_addr6[ETH_ALEN];
	} __packed machdr;

	__le16	   fn:4, sn:12;
} __packed;

struct beacon_pkts {
	struct meshidhdr	meshid_elem;
	struct meshconfhdr	meshconf_elem;
	u32					fcs;
} __packed;

struct preq_pkts {
	u8		category;
	u8		action;
	struct {
		u8		tag;
		u8		len;
		u8		flags;
		u8		hop_count;
		u8		ttl;
		u32		preq_id;
		u8		h_origaddr[ETH_ALEN];
		u32		orig_sn;
		u32		lifetime;
		u32		metric;
		u8		target_cnt;
		u8		per_target_flags;
		u8		h_targetaddr[ETH_ALEN];
		u32		target_sn;
	} __packed elem;

	u32		fcs;
} __packed;

struct prep_pkts {
	u8		category;
	u8		action;
	struct {
		u8			tag;
		u8			len;
		u8			flags;
		u8			hop_count;
		u8			ttl;
		u8			h_targetaddr[ETH_ALEN];
		u32			target_sn;
		u32			lifetime;
		u32			metric;
		u8			h_origaddr[ETH_ALEN];
		u32			orig_sn;
	} __packed elem;
	u32		fcs;
} __packed;

struct perr_pkts {
	u8		category;
	u8		action;
	struct {
		u8			tag;
		u8			len;
		u8			ttl;
		u8			flags;
		u8			h_targetaddr[ETH_ALEN];
		u8			target_sn;
		u16			target_rcode;
	} __packed elem;
	u32		fcs;
} __packed;

struct self_prot {
	u8		category;
	u8		action;
	struct meshidhdr	meshid_elem;
	struct meshconfhdr	meshconf_elem;
	struct mpm_hdr		mpm_elem;
} __packed;

struct ak60211s_hdr {
	u8 flags;
	u8 ttl;
	__le32 seqnum;
	u16 foffset;
	__le16 ethtype;
} __packed;

struct plc_packet_union {
	u8	da[ETH_ALEN];
	u8	sa[ETH_ALEN];
	__le16	ethtype;

	struct plc_hdr	plchdr;

	union {
		struct beacon_pkts	beacon;
		struct preq_pkts	preq;
		struct prep_pkts	prep;
		struct perr_pkts	perr;
		struct self_prot	self;
		struct ak60211s_hdr	meshhdr;
		u8 data[1520];
	} un;
};

static inline void ak60211_dev_lock(struct ak60211_if_data *dev)
	__acquires(&dev->mtx)
{
	mutex_lock(&dev->mtx);
	__acquire(&dev->mtx);
}

static inline void ak60211_dev_unlock(struct ak60211_if_data *dev)
	__releases(&dev->mtx)
{
	mutex_unlock(&dev->mtx);
	__release(&dev->mtx);
}

static inline struct ak60211_sta_info *
ak60211_next_hop_deref_protected(struct ak60211_mesh_path *mpath)
{
	return rcu_dereference_protected(mpath->next_hop,
					 lockdep_is_held(&mpath->state_lock));
}

extern struct net_bridge_hmc *plc;
extern bool plc_dbg;

extern const struct rhashtable_params ak60211_sta_rht_params;
extern const struct meshprofhdr local_prof;
extern const u8 broadcast_addr[ETH_ALEN];

int ak60211_mpath_tbl_init(struct ak60211_if_data *sdata);
void ak60211_mtbl_expire(struct ak60211_if_data *ifmsh);
bool ak60211_mesh_init(u8 *id, u8 *mac);
void ak60211_mpath_start_discovery(struct ak60211_if_data *ifmsh);
struct ak60211_mesh_path *ak60211_mpath_lookup(struct ak60211_if_data *ifmsh,
					       const u8 *dst);
void ak60211_mesh_deinit(void);
void ak60211_mtbl_deinit(struct ak60211_if_data *ifmsh);
int ak60211_rx_handler(struct sk_buff *pskb, struct sk_buff *nskb);
void ak60211_mesh_rx_plink_frame(struct ak60211_if_data *ifmsh,
				 struct plc_packet_union *buff);
void ak60211_mesh_rx_path_sel_frame(struct ak60211_if_data *ifmsh,
				    struct plc_packet_union *buff);
struct ak60211_mesh_path *ak60211_mpath_add(struct ak60211_if_data *ifmsh,
					    const u8 *dst);
void ak60211_mesh_plink_frame_tx(struct ak60211_if_data *ifmsh,
				 enum ak60211_sp_actioncode action,
				 u8 *addr, u16 llid, u16 plid);
int ak60211_mesh_match_local(struct meshprofhdr *peer);
void ak60211_mesh_neighbour_update(struct ak60211_if_data *ifmsh,
				   struct plc_packet_union *buff);
struct ak60211_sta_info *ak60211_mesh_sta_alloc(struct ak60211_if_data *ifmsh,
						u8 *addr);
struct ak60211_sta_info *mesh_info(struct ak60211_if_data *ifmsh, u8 *addr);
struct ak60211_sta_info *mesh_sta_info_get(struct ak60211_if_data *ifmsh,
					   u8 *addr);
inline bool ak60211_mplink_avaliables(struct ak60211_if_data *ifmsh);
void ak60211_pkt_hex_dump(struct sk_buff *skb, const char *type, int offset);
int ak60211_mpath_sel_frame_tx(enum ak60211_mpath_frame_type action,
			       u8 flags, const u8 *orig_addr, u32 orig_sn,
			       const u8 *target, u32 target_sn, const u8 *da,
			       u8 hop_count, u8 ttl, u32 lifetime, u32 metric,
			       u32 preq_id, struct ak60211_if_data *ifmsh);

void plc_send_beacon(void);
void ak60211_preq_test_wq(struct work_struct *work);
//void ak60211_mpath_queue_preq_new(struct hmc_hybrid_path *hmpath);
//int __ak60211_mpath_queue_preq_new(struct ak60211_if_data *ifmsh,
//				   struct hmc_hybrid_path *hmpath, u8 flags);
int ak60211_mpath_queue_preq(const u8 *addr);
int __ak60211_mpath_queue_preq(struct ak60211_if_data *ifmsh,
									const u8 *dst, u8 flags);
struct ak60211_if_data *ak60211_dev_to_ifdata(void);
int ak60211_mesh_hmc_ops_register(const struct ak60211_hmc_ops *ops);
void ak60211_mesh_hmc_ops_unregister(void);

void ak60211_mplink_timer(struct timer_list *t);
int ak60211_mpath_error_tx(struct ak60211_if_data *ifmsh, u8 ttl, const u8 *target,
							u32 target_sn, u16 target_rcode, const u8 *ra);
void __ak60211_mpath_del(struct ak60211_mesh_table *tbl,
				struct ak60211_mesh_path *mpath);
void ak60211_mesh_plink_fsm_restart(struct ak60211_sta_info *sta);

#endif
