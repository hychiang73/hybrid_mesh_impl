#include "mac60211.h"

#define MAX_METRIC	0xffffffff

#ifndef MSEC_TO_TU
#define MSEC_TO_TU(x)   (x*1000/1024)
#endif

#ifndef SN_GT
#define SN_GT(x, y) ((s32)(y - x) < 0)
#endif
#ifndef SN_LT
#define SN_LT(x, y) ((s32)(x - y) < 0)
#endif

enum ak60211_mpath_frame_type {
	AK60211_MPATH_PREQ = 0,
	AK60211_MPATH_PREP,
	AK60211_MPATH_PERR,
	AK60211_MPATH_RANN
};

static int ak60211_mpath_sel_frame_tx(enum ak60211_mpath_frame_type action, const u8 *orig_addr, u32 orig_sn, 
                        const u8 *target, u32 target_sn, const u8* da, u8 hop_count, u8 ttl, u32 lifetime, 
                        u32 metric, u32 preq_id, const u8 *sa);
static struct ak60211_mpath mesh_path[MAX_PATH_NUM] = {0};
struct net_bridge_hmc *dev;
static struct ak60211_sta_info mesh_sta[MAX_STA_NUM] = {0};
static struct if_plcmesh    plcmesh = {0};
const u8 broadcast_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

const struct meshprofhdr local_prof = {
    .meshid_elem.elemid = 114,
    .meshid_elem.len = MESHID_SIZE,
    .meshid_elem.meshid = "AkiraNet",

    .meshconf_elem.elemid = 113,
    .meshconf_elem.len = 7,
    .meshconf_elem.psel_protocol = 1,
    .meshconf_elem.psel_metric = 0,
    .meshconf_elem.congestion_ctrl_mode = 0,
    .meshconf_elem.sync_method = 0,
    .meshconf_elem.auth_protocol = 0,

    .meshconf_elem.mesh_formation.connected_to_gate = 0,
    .meshconf_elem.mesh_formation.num_of_peerings = 0,
    .meshconf_elem.mesh_formation.connected_as = 0,

    .meshconf_elem.mesh_cap.accepting_addi_mesh_peerings = 1,
    .meshconf_elem.mesh_cap.mcca_sup = 0,
    .meshconf_elem.mesh_cap.mcca_en = 0,
    .meshconf_elem.mesh_cap.forwarding = 1,
    .meshconf_elem.mesh_cap.mbca_en = 0,
    .meshconf_elem.mesh_cap.tbtt_adjusting = 0,
    .meshconf_elem.mesh_cap.ps = 0,
    .meshconf_elem.mesh_cap.reserved = 0,
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

void cf60211_get_dev(struct net_bridge_hmc *plc)
{
    TRACE();
    dev = plc;
    if (!dev) {
        hmc_err("get dev fail");
    } else {
        hmc_info("plc addr = %2x:%2x:%2x:%2x:%2x:%2x\n", dev->br_addr[0],dev->br_addr[1],   \
               dev->br_addr[2],dev->br_addr[3],dev->br_addr[4],dev->br_addr[5]);
    }
}

static void ak60211_sta_info_init(struct ak60211_sta_info* sta)
{
    if (sta->plink_state == AK60211_PLINK_ESTAB && 
            sta->processed_beacon) {
        return;
    }
    sta->processed_beacon = true;
}

static struct ak60211_sta_info* ak60211_sta_alloc(u8 *addr)
{
    struct ak60211_sta_info *sta = NULL;
    u8 i;
    for (i = 0; i < MAX_STA_NUM; i++) {
        if (!mesh_sta[i].used) {
            memcpy(mesh_sta[i].addr, addr, 6);
            mesh_sta[i].used = true;
            sta = &mesh_sta[i];
            break;
        }
    }
    if (!sta) {
        return NULL;
    }

    sta->plink_state = AK60211_PLINK_LISTEN;
    return sta;
}

static struct ak60211_sta_info* mesh_info(u8 *addr)
{
    struct ak60211_sta_info* sta = NULL;
    u8 i;
    for (i = 0; i < MAX_STA_NUM; i++) {
        if (!memcmp(addr, mesh_sta[i].addr, 6)) {
            sta = &mesh_sta[i];
            break;
        }
    }

    return sta;
}

static struct ak60211_sta_info* mesh_sta_info_get(u8 *addr)
{
    struct ak60211_sta_info* sta = mesh_info(addr);
    
    if (sta) {
        ak60211_sta_info_init(sta);
    } else {
        sta = ak60211_sta_alloc(addr);

        if (!sta) {
            hmc_err("mesh sta alloc fail");
            return NULL;
        }

        ak60211_sta_info_init(sta);
    }

    return sta;
}

static struct ak60211_mpath *ak60211_mpath_lookup(const u8 *dst)
{
    int i;
    for (i = 0; i < MAX_PATH_NUM; i++) {
        if (ether_addr_equal(dst, mesh_path[i].dst)) {
            return &mesh_path[i];
        }
    }

    return NULL;
}

static struct ak60211_mpath *ak60211_mpath_new(const u8 *dst)
{
    int i;
    struct ak60211_mpath *new_mpath;
    for (i = 0; i < MAX_PATH_NUM; i++) {
        if (!mesh_path[i].is_used) {
            new_mpath = &mesh_path[i];
            new_mpath->is_used = true;
            memcpy(new_mpath, dst, ETH_ALEN);

            eth_broadcast_addr(new_mpath->rann_snd_addr);
            new_mpath->is_root = false;
            new_mpath->flags = 0;
            new_mpath->exp_time = jiffies;

            // todo: timer_setup (mesh_path_timer)

            return new_mpath;
        }
    }

    return NULL;
}

static struct ak60211_mpath *ak60211_mpath_add(const u8 *dst)
{
    struct ak60211_mpath *new_mpath;
    int i, max_used = true;

    if (ether_addr_equal(dst, dev->br_addr)) {
        hmc_err("dst is equal to dev->br_addr no support");
        return false;
    }

    if (is_multicast_ether_addr(dst)) {
        hmc_err("dst is multicast no support");
        return false;
    }

    for (i = 0; i < MAX_PATH_NUM; i++) {
        if (!mesh_path[i].is_used) {
            max_used = false;
            break;
        }
    }

    if (max_used) {
        hmc_err("mpath is max size");
        return false;
    }

    new_mpath = ak60211_mpath_new(dst);

    if (!new_mpath) {
        hmc_err("mpath allocate fail");
        return false;
    }
    
    return new_mpath;
}

static bool ak60211_llid_in_use(u16 llid)
{
    int i;
    for (i = 0; i < MAX_STA_NUM; i++) {
        if (mesh_sta[i].used) {
            if (mesh_sta[i].llid == llid) {
                return true;
            }
        }
    }

    return false;
}

static u16 ak60211_mesh_get_new_llid(void)
{
    u16 llid;

    do {
        get_random_bytes(&llid, sizeof(llid));
    } while(ak60211_llid_in_use(llid));

    return llid;
}

static inline void ak60211_mesh_plink_timer_set(struct ak60211_sta_info *sta, u32 timeout)
{
    sta->plink_timeout = timeout;
    mod_timer(&sta->plink_timer, jiffies + msecs_to_jiffies(timeout));
}

void ak60211_pkt_hex_dump(struct sk_buff *skb, const char* type, int offset)
{
        size_t len;
        int rowsize = 16;
        int i, l, linelen, remaining;
        int li = 0;
        u8 *data, ch; 

        data = (u8 *) skb_mac_header(skb);
       //data = (u8 *) skb->head;

        if (skb_is_nonlinear(skb)) {
                len = skb->data_len;
        } else {
                len = skb->len;
        }

        remaining = len + 2 + offset;
        printk("Packet hex dump (len = %ld):\n", len);
        printk("============== %s ==============\n", type);
        for (i = 0; i < len; i += rowsize) {
                printk("%06d\t", li);

                linelen = min(remaining, rowsize);
                remaining -= rowsize;

                for (l = 0; l < linelen; l++) {
                        ch = data[l];
                        printk(KERN_CONT "%02X ", (uint32_t) ch);
                }

                data += linelen;
                li += 10; 

                printk(KERN_CONT "\n");
        }
        printk("====================================\n");
}

static void ak60211_mesh_plink_frame_tx(enum ieee80211_self_protected_actioncode action, u8 *addr, u16 llid, u16 plid)
{
    struct sk_buff *nskb;
    struct ethhdr *ether;
    struct plc_hdr *plchdr;
    u8 *pos;

    /*
     * headroom + ETH header + plchdr + action + fcs + reserved
     */
    nskb = dev_alloc_skb(2 + ETH_HLEN +
            42 + 79 + 4 + 2);
    if (!nskb) {
        hmc_err("no space to allocate");
        return;
    }

    skb_reserve(nskb, 2);
    
    ether = (struct ethhdr *)skb_put_zero(nskb, ETH_HLEN);

    memcpy(ether->h_dest, addr, ETH_ALEN);
    memcpy(ether->h_source, dev->br_addr, ETH_ALEN);
    ether->h_proto = ntohs(0xAA55);

    /* plc hdr*/
    plchdr = skb_put_zero(nskb, 42);
    plchdr->framectl = cpu_to_le16(AK60211_FTYPE_MGMT |
                         AK60211_STYPE_ACTION);

    plchdr->duration_id = 0;

    memcpy(plchdr->machdr.h_addr1, addr, 6);
    memcpy(plchdr->machdr.h_addr3, addr, 6);
    memcpy(plchdr->machdr.h_addr2, dev->br_addr, 6);
    memcpy(plchdr->machdr.h_addr4, dev->br_addr, 6);

    plchdr->fn = 0;
    plchdr->sn = ++plcmesh.mgmt_sn;

    pos = skb_put_zero(nskb, 79);
    // category
    *pos++ = WLAN_CATEGORY_SELF_PROTECTED;
    
    // action
    *pos++ = action;

    // meshid + meshconf
    memcpy(pos, &local_prof, sizeof(local_prof));
    pos = pos+sizeof(local_prof);

    // mpm_elem
    // mesh peer protocol
    *pos++ = 117;
    *pos++ = 4;
    put_unaligned_le16(0x0000, pos);
    pos += 2;

    // llid
    put_unaligned_le16(llid, pos);
    pos += 2;

    // plid
    if (action == WLAN_SP_MESH_PEERING_CONFIRM) {
        put_unaligned_le16(plid, pos);
    }
    pos += 2;

    // reason
    if (action == WLAN_SP_MESH_PEERING_CLOSE) {
        put_unaligned_le16(0x0, pos);
    }
    pos += 2;

    skb_reset_mac_header(nskb);

    ak60211_pkt_hex_dump(nskb, "ak60211_send", 0);

    br_hmc_forward(nskb, dev);
}

static void ak60211_mesh_plink_open(struct ak60211_sta_info *sta, struct plc_packet_union *buff)
{
    sta->llid = ak60211_mesh_get_new_llid();
    if (sta->plink_state != AK60211_PLINK_LISTEN) {
        return;
    }

    sta->plink_state = AK60211_PLINK_OPN_SNT;
    // todo: add timeout function ak60211_mesh_plink_timer_set(sta, AK60211MESH_RETRY_TIMEOUT);

    hmc_info("Mesh plink: start estab with %pM\n", sta->addr);

    ak60211_mesh_plink_frame_tx(WLAN_SP_MESH_PEERING_OPEN, buff->plchdr.machdr.h_addr4, sta->llid, 0);
}

static void ak60211_mesh_neighbour_update(struct plc_packet_union *buff)
{
    struct ak60211_sta_info *sta;
    sta = mesh_sta_info_get(buff->plchdr.machdr.h_addr4);

    if(!sta) {
        goto out;
    }
    if (sta->plink_state == AK60211_PLINK_LISTEN) {
        ak60211_mesh_plink_open(sta, buff);
    }
out:
    return;
}

static int ak60211_mesh_match_local(struct meshprofhdr *peer) 
{
    if (!(peer->meshid_elem.elemid == local_prof.meshid_elem.elemid &&
        peer->meshid_elem.len == local_prof.meshid_elem.len &&
        !memcmp(peer->meshid_elem.meshid, local_prof.meshid_elem.meshid, MESHID_SIZE) &&
        peer->meshconf_elem.psel_protocol == local_prof.meshconf_elem.psel_protocol &&
        peer->meshconf_elem.psel_metric == local_prof.meshconf_elem.psel_metric &&
        peer->meshconf_elem.congestion_ctrl_mode == local_prof.meshconf_elem.congestion_ctrl_mode &&
        peer->meshconf_elem.sync_method == local_prof.meshconf_elem.sync_method &&
        peer->meshconf_elem.auth_protocol == local_prof.meshconf_elem.auth_protocol )) {
        hmc_err("mesh do not match!!");
        return false;
    }

    return true;
}

static inline bool ak60211_mesh_plink_free_avaliable(void)
{
    int i;
    
    for (i = 0; i < 16; i++) {
        if (!mesh_sta[i].used) {
            return true;
        }
    }

    return false;
}

static enum ak60211_plink_event ak60211_plink_get_event(u16 ftype, u16 plid, u16 llid, struct plc_packet_union *buff, struct ak60211_sta_info *sta)
{
    enum ak60211_plink_event event = PLINK_UNDEFINED;
    bool matches_local;
    struct meshprofhdr peer;

    memcpy(&peer.meshid_elem, &buff->un.self.meshid_elem, sizeof(struct meshidhdr));
    memcpy(&peer.meshconf_elem, &buff->un.self.meshconf_elem, sizeof(struct meshconfhdr));

    matches_local = ak60211_mesh_match_local(&peer);

    if (!matches_local && !sta) {
        event = OPN_RJCT;
        goto out;
    }

    if (!sta) {
        if (ftype != WLAN_SP_MESH_PEERING_OPEN) {
            hmc_err("Mesh plink: cls or cnf from unknown peer");
            goto out;
        }

       if (!ak60211_mesh_plink_free_avaliable()) {
           hmc_err("Mesh plink: no more free plinks");
           goto out;
       }

       event = OPN_ACPT;
       goto out;
    } else {
        if (sta->plink_state == AK60211_PLINK_BLOCKED) {
            goto out;
        }
    }

    switch(ftype) {
        case WLAN_SP_MESH_PEERING_OPEN:
            if (!matches_local) {
                event = OPN_RJCT;
            }
            if (!ak60211_mesh_plink_free_avaliable() ||
                    (sta->plid && sta->plid != plid)) {
                event = OPN_IGNR;
            } else {
                event = OPN_ACPT;
            }
            break;
        case WLAN_SP_MESH_PEERING_CONFIRM:
            if (!matches_local) {
                event = CNF_RJCT;
            }
            if (!ak60211_mesh_plink_free_avaliable() ||
                    sta->llid != llid ||
                    (sta->plid && sta->plid != plid)) {
                event = CNF_IGNR;
            } else {
                event = CNF_ACPT;
            }
            break;
        case WLAN_SP_MESH_PEERING_CLOSE:
            if (sta->plink_state == AK60211_PLINK_ESTAB) {
                event = CLS_ACPT;
            } else if (sta->plid != plid) {
                event = CLS_IGNR;
            } else if (sta->llid && sta->llid != llid) {
                event = CLS_IGNR;
            } else {
                event = CLS_ACPT;
            }
            break;
        default:
            break;
    }

out:
    return event;
}

static inline void ak60211_mesh_plink_fsm_restart(struct ak60211_sta_info *sta)
{
    sta->plink_state = AK60211_PLINK_LISTEN;
    sta->llid = sta->plid = sta->reason = 0;
}

static void ak60211_mesh_plink_close(struct ak60211_sta_info *sta, enum ak60211_plink_event event)
{
    u16 reason = (event == CLS_ACPT)? WLAN_REASON_MESH_CLOSE : WLAN_REASON_MESH_CONFIG;

    sta->plink_state = AK60211_PLINK_HOLDING;
    sta->reason = reason;
}

static void ak60211_mesh_plink_establish(struct ak60211_sta_info *sta)
{
    sta->plink_state = AK60211_PLINK_ESTAB;
    hmc_info("Mesh plink with %pM ESTABLISHED\n", sta->addr);
}

static void ak60211_mesh_plink_fsm(enum ak60211_plink_event event, struct ak60211_sta_info *sta, struct plc_packet_union *buff)
{
    enum ieee80211_self_protected_actioncode action = 0;

    TRACE();
    hmc_info("peer %pM in state %s got events %s", sta->addr, mplstates[sta->plink_state], mplevents[event]);

    switch(sta->plink_state) {
        case AK60211_PLINK_LISTEN:
            switch (event) {
                case CLS_ACPT:
                    ak60211_mesh_plink_fsm_restart(sta);
                    break;
                case OPN_ACPT:
                    sta->plink_state = AK60211_PLINK_OPN_RCVD;
                    sta->llid = ak60211_mesh_get_new_llid();

                    action = WLAN_SP_MESH_PEERING_OPEN;
                    break;
                default:
                    break;
            }
            break;
        case AK60211_PLINK_OPN_SNT:
            switch(event) {
                case OPN_RJCT:
                case CNF_RJCT:
                case CLS_ACPT:
                    ak60211_mesh_plink_close(sta, event);
                    action = WLAN_SP_MESH_PEERING_CLOSE;
                    break;
                case OPN_ACPT:
                    sta->plink_state = AK60211_PLINK_OPN_RCVD;
                    action = WLAN_SP_MESH_PEERING_CONFIRM;
                    break;
                case CNF_ACPT:
                    sta->plink_state = AK60211_PLINK_CNF_RCVD;
                    break;
                default:
                    break;
            }
            break;
        case AK60211_PLINK_OPN_RCVD:
            switch(event) {
                case OPN_RJCT:
                case CNF_RJCT:
                case CLS_ACPT:
                    ak60211_mesh_plink_close(sta, event);
                    action = WLAN_SP_MESH_PEERING_CLOSE;
                    break;
                case OPN_ACPT:
                    action = WLAN_SP_MESH_PEERING_CONFIRM;
                    break;
                case CNF_ACPT:
                    ak60211_mesh_plink_establish(sta);
                    break;
                default:
                    break;
            }
            break;
        case AK60211_PLINK_CNF_RCVD:
            switch(event) {
                case OPN_RJCT:
                case CNF_RJCT:
                case CLS_ACPT:
                    ak60211_mesh_plink_close(sta, event);
                    action = WLAN_SP_MESH_PEERING_CLOSE;
                    break;
                case OPN_ACPT:
                    ak60211_mesh_plink_establish(sta);
                    action = WLAN_SP_MESH_PEERING_CONFIRM;
                    break;
                default:
                    break;
            }
            break;
        case AK60211_PLINK_ESTAB:
            switch(event) {
                case CLS_ACPT:
                    ak60211_mesh_plink_close(sta, event);
                    action = WLAN_SP_MESH_PEERING_CLOSE;
                    break;
                case OPN_ACPT:
                    action = WLAN_SP_MESH_PEERING_CONFIRM;
                    break;
                default:
                    break;
            }
            break;
        case AK60211_PLINK_HOLDING:
            switch(event) {
                case CLS_ACPT:
                    ak60211_mesh_plink_fsm_restart(sta);
                    break;
                case OPN_ACPT:
                case CNF_ACPT:
                case OPN_RJCT:
                case CNF_RJCT:
                    action = WLAN_SP_MESH_PEERING_CLOSE;
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }

    if (action) {
        ak60211_mesh_plink_frame_tx(action, buff->plchdr.machdr.h_addr4, sta->llid, sta->plid);

        if (action == WLAN_SP_MESH_PEERING_OPEN) {
            ak60211_mesh_plink_frame_tx(WLAN_SP_MESH_PEERING_CONFIRM, buff->plchdr.machdr.h_addr4, sta->llid, sta->plid);
        }
    }
}
static void ak60211_mesh_rx_plink_frame(struct plc_packet_union *buff)
{    
    struct ak60211_sta_info *sta;
    u16 ftype;
    u16 plid, llid = 0;
    enum ak60211_plink_event event;

    ftype = buff->un.self.action;
    if (is_multicast_ether_addr(buff->da)) {
        hmc_err("Mesh plink: ignore frame from multicast");
        return;
    }

    plid = get_unaligned_le16(&buff->un.self.mpm_elem.llid);
    if (ftype == WLAN_SP_MESH_PEERING_CONFIRM) {
        llid = get_unaligned_le16(&buff->un.self.mpm_elem.plid);
    }

    sta = mesh_info(buff->plchdr.machdr.h_addr4);

    // todo: check rssi threshold
    
    event = ak60211_plink_get_event(ftype, plid, llid, buff, sta);

    if (event == OPN_ACPT) {
        sta = mesh_sta_info_get(buff->plchdr.machdr.h_addr4);
        if (!sta) {
            hmc_err("Mesh plink: failed to init peer!\n");
        }
        sta->plid = plid;
    } else if (!sta && event == OPN_RJCT) {
        ak60211_mesh_plink_frame_tx(WLAN_SP_MESH_PEERING_OPEN, buff->plchdr.machdr.h_addr4, 0, plid);
    }

    if (event == CNF_ACPT) {
        if (!sta->plid) {
            sta->plid = plid;
        }
    }

    ak60211_mesh_plink_fsm(event, sta, buff);
}

static u32 ak60211_plc_link_metric_get(struct ak60211_sta_info *sta)
{
    return 10;
}

static u32 ak60211_hwmp_route_info_get(struct plc_packet_union *buff, enum ak60211_mpath_frame_type action)
{
    struct ak60211_sta_info *sta;
    struct ak60211_mpath *mpath;
    bool fresh_info;
    const u8 *orig_addr;
    u32 orig_sn, orig_metric;
    unsigned long orig_lifetime, exp_time;
    u32 last_hop_metric, new_metric;
    bool process = true;
    u8 hopcount;

    sta = mesh_info(buff->plchdr.machdr.h_addr2);
    if (!sta) {
        return 0;
    }

    /* todo: metric get??*/
    last_hop_metric = ak60211_plc_link_metric_get(sta);

    /* Update and check originator routing info */
    fresh_info = true;

    switch(action) {
        case AK60211_MPATH_PREQ:
            orig_addr = buff->un.preq.elem.h_origaddr;
            orig_sn = buff->un.preq.elem.orig_sn;
            orig_lifetime = buff->un.preq.elem.lifetime;
            orig_metric = buff->un.preq.elem.metric;
            hopcount = buff->un.preq.elem.hop_count + 1;
            break;
        case AK60211_MPATH_PREP:
            orig_addr = buff->un.prep.elem.h_targetaddr;
            orig_sn = buff->un.prep.elem.target_sn;
            orig_lifetime = buff->un.prep.elem.lifetime;
            orig_metric = buff->un.prep.elem.metric;
            hopcount = buff->un.prep.elem.hop_count + 1;
            break;
        default:
            return 0;
    }

    new_metric = orig_metric + last_hop_metric;
    if (new_metric < orig_metric) {
        new_metric = MAX_METRIC;
    }
    exp_time = TU_TO_EXP_TIME(orig_lifetime);

    if (ether_addr_equal(orig_addr, dev->br_addr)) {
        process = false;
        fresh_info = false;
    } else {
        mpath = ak60211_mpath_lookup(orig_addr);
        if (mpath) {
            if (mpath->flags & MESH_PATH_FIXED) {
                fresh_info = false;
            } else if (mpath->is_used) {
                if (SN_GT(mpath->sn, orig_sn) ||
                        (mpath->sn == orig_sn &&
                        (!ether_addr_equal(mpath->next_hop, sta->addr)? mult_frac(new_metric, 10, 9) : 
                         new_metric) >= mpath->metric)) {
                    process = false;
                    fresh_info = false;
                }       
            }
        } else {
            mpath = ak60211_mpath_add(orig_addr);
            if (!mpath) {
                return 0;
            }
        }

        if (fresh_info) {
            ;/* todo: fresh_info for originator frame and transmitter frame */
        }
    }

    /* todo: Update and check transmitter routing info */

    return process? new_metric : 0;
}

static void ak60211_hwmp_preq_frame_process(struct plc_packet_union *buff, u32 orig_metric)
{
    struct ak60211_mpath *mpath = NULL;
    const u8 *target_addr, *orig_addr;
    const u8 *da;
    u8 target_flags, ttl, flags;
    u32 orig_sn, target_sn, lifetime, target_metric = 0;
    bool reply = false;
    bool forward = true;
    bool root_is_gate;

    /* Update target SN, if present */
    target_addr = buff->un.preq.elem.h_targetaddr;
    orig_addr = buff->un.preq.elem.h_origaddr;
    target_sn = buff->un.preq.elem.target_sn;
    orig_sn = buff->un.preq.elem.orig_sn;
    target_flags = buff->un.preq.elem.per_target_flags;
    
    flags = buff->un.preq.elem.flags;
    root_is_gate = !!(flags & RANN_FLAG_IS_GATE);

    hmc_info("received PREQ from %pM\n", orig_addr);

    if (ether_addr_equal(target_addr, dev->br_addr)) {
        hmc_info("PREQ is for us\n");
        forward = false;
        reply = true;
        target_metric = 0;

        if (SN_GT(target_sn, plcmesh.sn)) {
            plcmesh.sn = target_sn;
        }

        if (time_after(jiffies, plcmesh.last_sn_update + 
                   msecs_to_jiffies(MESH_TRAVERSAL_TIME)) || 
                time_before(jiffies, plcmesh.last_sn_update)) {
            plcmesh.sn++;
            plcmesh.last_sn_update = jiffies;
        }

        target_sn = plcmesh.sn;
    } else if (is_broadcast_ether_addr(target_addr)) {
        /* target only and broadcast will go in here */
        mpath = ak60211_mpath_lookup(orig_addr);
        if (mpath) {
            reply = true;
            target_addr = dev->br_addr;
            target_sn = ++plcmesh.sn;
            target_metric = 0;
            plcmesh.last_sn_update = jiffies;
        }
        if (root_is_gate) {
            /* todo: mesh_path_add_gate() */
        }

    } else {
        mpath = ak60211_mpath_lookup(target_addr);
        if (mpath) {
            if (SN_LT(mpath->sn, target_sn)) {
                mpath->sn = target_sn;
                mpath->flags |= MESH_PATH_SN_VALID;
            }
        }
    }

    if (reply) {
        lifetime = buff->un.preq.elem.lifetime;
        ttl = MAX_MESH_TTL;
        if (ttl != 0) {
            hmc_info("replying to the PREQ\n");
            ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREP, orig_addr, orig_sn, target_addr, target_sn, buff->sa, 
                                       0, ttl, lifetime, target_metric, 0, dev->br_addr);

        }
    }

    if (forward) {
        u32 preq_id;
        u8 hopcount;

        ttl = buff->un.preq.elem.ttl;
        lifetime = buff->un.preq.elem.lifetime;
        if (ttl <= 1) {
            return;
        }

        hmc_info("forwarding the PREQ from %pM\n", orig_addr);
        --ttl;
        preq_id = buff->un.preq.elem.preq_id;
        hopcount = buff->un.preq.elem.hop_count + 1;
        da = (mpath && mpath->is_root)? mpath->rann_snd_addr : broadcast_addr;

        ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREQ, orig_addr, orig_sn, target_addr, target_sn, da, 
                                   hopcount, ttl, lifetime, orig_metric, preq_id, dev->br_addr);
    }
}

static void ak60211_mesh_rx_path_sel_frame(struct plc_packet_union *buff)
{
    u32 path_metric;
    struct ak60211_sta_info *sta;
    enum ak60211_mpath_frame_type tag = buff->un.preq.elem.tag;
    sta = mesh_info(buff->plchdr.machdr.h_addr2);
    if (!sta || sta->plink_state != AK60211_PLINK_ESTAB) {
        return;
    }

    switch(tag) {
        case AK60211_MPATH_PREQ:
            if (buff->un.preq.elem.len != 37) {
                return;
            }
            path_metric = ak60211_hwmp_route_info_get(buff, AK60211_MPATH_PREQ);

            if (path_metric) {
                ak60211_hwmp_preq_frame_process(buff, path_metric);
            }
            break;
        default:
            break;
    }
}

static void ak60211_mesh_rx_mgmt_action(struct plc_packet_union *buff)
{
    switch(buff->un.self.category) {
        case WLAN_CATEGORY_SELF_PROTECTED:
            switch(buff->un.self.action) {
                case WLAN_SP_MESH_PEERING_OPEN:
                case WLAN_SP_MESH_PEERING_CLOSE:
                case WLAN_SP_MESH_PEERING_CONFIRM:
                    ak60211_mesh_rx_plink_frame(buff);
                    break;
            }
            break;
        case WLAN_CATEGORY_MESH_ACTION:
            if (buff->un.self.action == WLAN_MESH_ACTION_HWMP_PATH_SELECTION) {
                ak60211_mesh_rx_path_sel_frame(buff);
            }
            break;
    }
}

static int ak60211_mpath_sel_frame_tx(enum ak60211_mpath_frame_type action, const u8 *orig_addr, u32 orig_sn, 
                        const u8 *target, u32 target_sn, const u8* da, u8 hop_count, u8 ttl, u32 lifetime, 
                        u32 metric, u32 preq_id, const u8 *sa)
{
    struct sk_buff *skb;
    struct plc_packet_union *plcpkts;
    u8 *pos, ie_len;
    int hdr_len = sizeof(struct ethhdr) + sizeof(struct plc_hdr);

    switch(action) {
        case AK60211_MPATH_PREQ:
            hdr_len += sizeof(struct preq_pkts);
            break;
        case AK60211_MPATH_PREP:
            hdr_len += sizeof(struct prep_pkts);
            break;
        default:
            break;
    }
    skb = dev_alloc_skb(2 + hdr_len + 2);

    if (!skb) {
        return -1;
    }

    skb_reserve(skb, 2);
   
    pos = skb_put_zero(skb, hdr_len);
    plc_fill_ethhdr(pos, da, orig_addr, ntohs(0xAA55));

    plcpkts = (struct plc_packet_union *)pos;
    plcpkts->plchdr.framectl = cpu_to_le16(AK60211_FTYPE_MGMT |
                              AK60211_STYPE_ACTION);

    memcpy(plcpkts->plchdr.machdr.h_addr1, da, ETH_ALEN);
    memcpy(plcpkts->plchdr.machdr.h_addr2, sa, ETH_ALEN);
    memcpy(plcpkts->plchdr.machdr.h_addr3, sa, ETH_ALEN);

    plcpkts->un.preq.category = WLAN_CATEGORY_MESH_ACTION;
    plcpkts->un.preq.action = WLAN_MESH_ACTION_HWMP_PATH_SELECTION;

    pos = (u8 *)&plcpkts->un.preq.elem.tag;
    switch(action) {
        case AK60211_MPATH_PREQ:
            hmc_info("seding PREQ to %pM\n", target);
            *pos++ = WLAN_EID_PREQ;
            ie_len = 37;
            break;
        case AK60211_MPATH_PREP:
            hmc_info("sending PREP to %pM\n", orig_addr);
            *pos++ = WLAN_EID_PREP;
            ie_len = 31;
            break;
        default:
            /* RANN and ERR */
            break;
    }

    *pos++ = ie_len;
    *pos++ = 0;
    *pos++ = hop_count;
    *pos++ = ttl;

    if (action == AK60211_MPATH_PREP) {
        memcpy(pos, target, ETH_ALEN);
        pos += ETH_ALEN;
        put_unaligned_le32(target_sn, pos);
        pos += 4;
    } else {
        if (action == AK60211_MPATH_PREQ) {
            put_unaligned_le32(preq_id, pos);
            pos += 4;
        }
        memcpy(pos, orig_addr, ETH_ALEN);
        pos += ETH_ALEN;
        put_unaligned_le32(orig_sn, pos);
        pos += 4;
    }
    put_unaligned_le32(lifetime, pos);
    pos += 4;
    put_unaligned_le32(metric, pos);
    pos += 4;
    if (action == AK60211_MPATH_PREQ) {
        *pos++ = 1;
        *pos++ = 0;
        memcpy(pos, target, ETH_ALEN);
        pos += ETH_ALEN;
        put_unaligned_le32(target_sn, pos);
        pos += 4;
    } else if (action == AK60211_MPATH_PREP) {
        memcpy(pos, orig_addr, ETH_ALEN);
        pos += ETH_ALEN;
        put_unaligned_le32(orig_sn, pos);
        pos += 4;
    }

    skb_reset_mac_header(skb);

    ak60211_pkt_hex_dump(skb, "ak60211_mpath_sel_frame_tx", 0);
    br_hmc_forward(skb, plc);

    return true;
}

void ak60211_mpath_discovery(void)
{
    struct ak60211_mpath *mpath;
    struct ak60211_sta_info *sta;
    const u8 *da;
    u8 *addr, ttl;
    u32 i, lifetime;

    for (i = 0; i < MAX_STA_NUM; i++) {
        sta = &mesh_sta[i];
        if (sta->used) {
            addr = sta->addr;
            mpath = ak60211_mpath_lookup(addr);

            if (!mpath) {
                mpath = ak60211_mpath_add(addr);
                if (!mpath) {
                    return;
                }
            }
            da = (mpath->is_root)? mpath->rann_snd_addr:broadcast_addr;
            ttl = MAX_MESH_TTL;
            lifetime = MSEC_TO_TU(2000);
            ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREQ, dev->br_addr, plcmesh.sn, mpath->dst, mpath->sn, da, 
                               0, ttl, lifetime, 0, plcmesh.preq_id++, dev->br_addr);
        }
    }
}

static void ak60211_mesh_bcn_presp(struct plc_packet_union *buff)
{
    struct meshprofhdr peer;
    u16 stype;
    
    stype = (le16_to_cpu(buff->plchdr.framectl) & AK60211_FCTL_STYPE);

    if (stype == AK60211_STYPE_PROBE_RESP && memcmp(buff->plchdr.machdr.h_addr3, dev->br_addr, 6)) {
        return;
    }

    memcpy(&peer.meshid_elem, &buff->un.beacon.meshid_elem, sizeof(struct meshidhdr));
    memcpy(&peer.meshconf_elem, &buff->un.beacon.meshconf_elem, sizeof(struct meshconfhdr));

    if (!ak60211_mesh_match_local(&peer)) {
        return;
    }

    ak60211_mesh_neighbour_update(buff);
}

int ak60211_rx_handler(struct sk_buff *pskb)
{
    struct sk_buff *skb = pskb;
    struct plc_packet_union *plcbuff;
    u16 stype, ftype;
    
    plcbuff = (struct plc_packet_union *)skb_mac_header(skb);

    if (!is_valid_ether_addr(plcbuff->sa)) {
        // not muitlcast or zero ether addr
        goto drop;
    }

    if ((!!memcmp(plcbuff->da, dev->br_addr, ETH_ALEN)) && !is_broadcast_ether_addr(plcbuff->da)) {
        goto drop;
    }

    hmc_info("eth type = %x\n", htons(plcbuff->ethtype));
    if (htons(plcbuff->ethtype) != 0xAA55) {
        goto drop;
    }

    ftype = (le16_to_cpu(plcbuff->plchdr.framectl) & AK60211_FCTL_FTYPE);
    stype = (le16_to_cpu(plcbuff->plchdr.framectl) & AK60211_FCTL_STYPE);

    switch(ftype) {
        case AK60211_FTYPE_MGMT:
            switch(stype) {
                case AK60211_STYPE_BEACON:
                    hmc_info("S_BEACON");
                    ak60211_mesh_bcn_presp(plcbuff);
                    break;
                case AK60211_STYPE_PROBE_RESP:
                    hmc_info("S_PROBE_RESP");
                    break;
                case AK60211_STYPE_ACTION:
                    hmc_info("S_ACTION");
                    ak60211_mesh_rx_mgmt_action(plcbuff);
                    break;
            }
            break;
        case AK60211_FTYPE_CTRL:

            break;
        case AK60211_FTYPE_DATA:
            switch(stype) {
                case AK60211_STYPE_QOSDATA:

                    hmc_info("S_QOSDATA");
                    break;
            }
            break;
    }

    return 0;

drop:
    return -1;
}
