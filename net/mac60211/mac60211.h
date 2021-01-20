// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 AkiraNET Corporation
 */

#ifndef MAC60211_H
#define MAC60211_H

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

#include "../bridge/br_private.h"

#define hmc_info(fmt, arg...)						            \
({									                            \
	pr_info("PLC: (%s, %d): " fmt, __func__, __LINE__, ##arg);	\
})									                            \

#define hmc_err(fmt, arg...)						            \
({									                            \
	pr_err("PLC: (%s, %d): " fmt, __func__, __LINE__, ##arg);	\
})									                            \

#define TRACE()     hmc_info("%s\n", __func__);
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define MESH_TRAVERSAL_TIME  50
#define SBEACON_DELAY   5000
#define SPATHDISC_DELAY 3000
#define MESHID_SIZE     30
#define MAX_STA_NUM     16
#define MAX_PATH_NUM    16
#define MAX_MESH_TTL    32
#define AK60211MESH_RETRY_TIMEOUT   5000

#define AK60211_FCTL_FTYPE      0x000c
#define AK60211_FCTL_STYPE      0x00f0

#define AK60211_FTYPE_MGMT          0x0000   // 0b00
#define AK60211_FTYPE_CTRL          0x0004   // 0b01
#define AK60211_FTYPE_DATA          0x0008   // 0b10

/* management */
#define AK60211_STYPE_BEACON        0x0080   // 0b1000
#define AK60211_STYPE_PROBE_REQ     0x0040   // 0b0100
#define AK60211_STYPE_PROBE_RESP    0x0050   // 0b0101
#define AK60211_STYPE_ACTION        0x00D0   // 0b1101

/* data */
#define AK60211_STYPE_QOSDATA       0x0080   // 0b1000

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

enum ak60211_mpath_flags {
	MESH_PATH_ACTIVE = BIT(0),
	MESH_PATH_RESOLVING = BIT(1),
	MESH_PATH_SN_VALID = BIT(2),
	MESH_PATH_FIXED = BIT(3),
	MESH_PATH_RESOLVED = BIT(4),
	MESH_PATH_REQ_QUEUED = BIT(5),
	MESH_PATH_DELETED = BIT(6),
};

struct ak60211_mpath {
    u8  dst[ETH_ALEN];
    u8  next_hop[ETH_ALEN];
    u32 sn;
    u32 metric;
    u8  hop_count;
    unsigned long exp_time;
    u32 discovery_timeout;
    u8  discovery_retries;
    enum ak60211_mpath_flags    flags;
    u8  rann_snd_addr[ETH_ALEN];
    u32 rann_metric;
    unsigned long last_preq_to_root;
    bool    is_root;
    bool    is_gate;
    bool    is_used;
};

struct if_plcmesh {
    // 802.11 mgmt sequence number
    u32        mgmt_sn;
    // 802.11 action sn
    u32        action_sn;
    // Local mesh sequence number
    u32        sn;
    // Last used PREQ id
    u32        preq_id;
    // Timestamp of last SN update
    unsigned long   last_sn_update;
    // Mesh data SN
    u32        mesh_seqnum;
    // Mesh nexthop
    u8        nexthop[6];
};

struct frametype {
    u16 reserved1:2, type:2, stype:4, reserved2:8;
};

struct meshidhdr {
    u8     elemid;
    u8     len;
    u8     meshid[MESHID_SIZE];
} __packed;

struct mesh_formation_info {
    u8   connected_to_gate:1;
    u8   num_of_peerings:6;
    u8   connected_as:1;
} __packed;

struct mesh_capability {
    u8   accepting_addi_mesh_peerings:1;
    u8   mcca_sup:1;
    u8   mcca_en:1;
    u8   forwarding:1;
    u8   mbca_en:1;
    u8   tbtt_adjusting:1;
    u8   ps:1;
    u8   reserved:1;
} __packed;

struct meshconfhdr {
    u8     elemid;
    u8     len;
    u8     psel_protocol;
    u8     psel_metric;
    u8     congestion_ctrl_mode;
    u8     sync_method;
    u8     auth_protocol;
    struct mesh_formation_info  mesh_formation;
    struct mesh_capability      mesh_cap;
} __packed;

struct meshprofhdr {
    struct meshidhdr    meshid_elem;
    struct meshconfhdr  meshconf_elem;
} __packed;

struct mpm_hdr {
    u8    meshid_elem;
    u8    len;
    u16   mesh_peer_protocol;
    u16   llid;
    u16   plid;
    u16   reason;
    u8    pmk[16];
} __packed;

struct plc_hdr {
    __le16     framectl;
    __le16     duration_id;
    struct {
        u8    h_addr1[ETH_ALEN];
        u8    h_addr2[ETH_ALEN];
        u8    h_addr3[ETH_ALEN];
        u8    h_addr4[ETH_ALEN];
        u8    h_addr5[ETH_ALEN];
        u8    h_addr6[ETH_ALEN];
    } __packed machdr;
        
    __le16     fn:4, sn:12;
} __packed;

struct beacon_pkts {
    struct meshidhdr    meshid_elem;
    struct meshconfhdr  meshconf_elem;
    u32                 fcs;
} __packed;

struct preq_pkts {
    u8      category;
    u8      action;
    struct {
        u8      tag;
        u8      len;
        u8      flags;
        u8      hop_count;
        u8      ttl;
        u32     preq_id;
        u8      h_origaddr[ETH_ALEN];
        u32     orig_sn;
        u32     lifetime;
        u32     metric;
        u8      target_cnt;
        u8      per_target_flags;
        u8      h_targetaddr[ETH_ALEN];
        u32     target_sn;
    } __packed elem;

    u32     fcs;
} __packed;

struct prep_pkts {
    u8      category;
    u8      action;
    struct {
        u8          tag;
        u8          len;
        u8          flags;
        u8          hop_count;
        u8          ttl;
        u8          h_targetaddr[ETH_ALEN];
        u32         target_sn;
        u32         lifetime;
        u32         metric;
        u8          h_origaddr[ETH_ALEN];
        u32         orig_sn;
    } __packed elem;
    u32     fcs;
} __packed;

struct self_prot{
    u8      category;
    u8      action;
    struct meshidhdr    meshid_elem;
    struct meshconfhdr  meshconf_elem;
    struct mpm_hdr      mpm_elem;
} __packed;

struct plc_packet_union {
    u8  da[ETH_ALEN];
    u8  sa[ETH_ALEN];
    __le16  ethtype;

    struct plc_hdr  plchdr;

    union {
        struct beacon_pkts  beacon;
        struct preq_pkts    preq;
        struct prep_pkts    prep;
        struct self_prot    self;
    } un;
};
   
struct ak60211_sta_info {
    struct timer_list           plink_timer;
    enum ak60211_plink_state    plink_state;
    u32     plink_timeout;
    u32     ewma_fail_avg;
    u16     llid;
    u16     plid;
    u16     reason;
    u16     processed_beacon:1, connected_to_gate:1, used:1, retry:8, reserved:5;
    u8      addr[6];
};

extern int ak60211_rx_handler(struct sk_buff *pskb);
extern struct net_bridge_hmc *plc;
extern void cf60211_get_dev(struct net_bridge_hmc *plc);
extern void plc_fill_ethhdr(u8 *st, const u8 *da, const u8 *sa, u16 type);
extern void ak60211_mpath_discovery(void);

extern const u8 broadcast_addr[ETH_ALEN];

#endif /* MAC60211_H */
