#include "mac60211.h"

struct net_bridge_hmc *dev;
static struct ak60211_sta_info mesh_sta[MAX_STA_NUM] = {0};
static struct if_plcmesh    plcmesh = {0};
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
    struct frametype fctl = {0};
    struct ethhdr *ether;
    struct plc_hdr *plchdr;
    u8 *pos;
    
    fctl.type = MGMT;
    fctl.stype = S_ACTION;

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
    memcpy(&plchdr->framectl, &fctl, 2);
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
                //ak60211_mesh_rx_path_sel_frame(buff);
            }
            break;
    }
}

static void ak60211_mesh_bcn_presp(struct plc_packet_union *buff)
{
    struct meshprofhdr peer;
    struct frametype fctl;
    *(u16*)&fctl = buff->plchdr.framectl;

    if (fctl.stype == S_PROBE_RESP && memcmp(buff->plchdr.machdr.h_addr3, dev->br_addr, 6)) {
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
    struct frametype fctl;
    
    plcbuff = (struct plc_packet_union *)skb_mac_header(skb);

    if (!is_valid_ether_addr(plcbuff->sa)) {
        // not muitlcast or zero ether addr
        goto drop;
    }

    if ((!!memcmp(plcbuff->da, dev->br_addr, ETH_ALEN)) && !is_broadcast_ether_addr(plcbuff->da)) {
        goto drop;
    }

    hmc_info("eth type = %x\n", htons(plcbuff->ethtype));
    if (htons(plcbuff->ethtype) != 0xAA55)
        goto drop;

    *(u16*)&fctl = plcbuff->plchdr.framectl;

    switch(fctl.type) {
        case MGMT:
            switch(fctl.stype) {
                case S_BEACON:
                    hmc_info("S_BEACON");
                    ak60211_mesh_bcn_presp(plcbuff);
                    break;
                case S_PROBE_RESP:
                    hmc_info("S_PROBE_RESP");
                    break;
                case S_ACTION:
                    hmc_info("S_ACTION");
                    ak60211_mesh_rx_mgmt_action(plcbuff);
                    break;
            }
            break;
        case CTRL:

            break;
        case DATA:
            switch(fctl.stype) {
                case S_QOSDATA:
                    hmc_info("S_QOSDATA");
                    break;
            }
            break;
    }

    return 0;

drop:
    return -1;
}
