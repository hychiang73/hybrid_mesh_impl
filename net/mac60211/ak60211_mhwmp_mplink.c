#include <ak60211_mesh_private.h>
#include <mac60211.h>

#define MSEC_TO_TU(x) (x*1000/1024)
#define SN_GT(x, y) ((s32)(y - x) < 0)
#define SN_LT(x, y) ((s32)(x - y) < 0)
#define MAX_SANE_SN_DELTA 32

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

static inline u32 ak60211_mplink_free_count(struct ak60211_if_data *ifmsh)
{
    return ifmsh->mshcfg.MeshMaxPeerLinks - atomic_read(&ifmsh->estab_plinks);
}

void __ak60211_mpath_queue_preq(struct ak60211_if_data *ifmsh, const u8 *dst, u32 hmc_sn)
{
    struct ak60211_mesh_path *mpath;
    u32 lifetime;
    u8 ttl;

    mpath = ak60211_mpath_lookup(ifmsh, dst);
    if (!mpath) {
        mpath = ak60211_mpath_add(ifmsh, dst);
        if (!mpath) {
            plc_err("mpath build up fail\n");
            return;
        }
    }

    ifmsh->sn = hmc_sn;
    ttl = MAX_MESH_TTL;
    lifetime = MSEC_TO_TU(AK60211_MESH_HWMP_PATH_TIMEOUT);
    ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREQ, mpath->flags, ifmsh->addr, ifmsh->sn, mpath->dst, mpath->sn, broadcast_addr, 
                               0, ttl, lifetime, 0, ++ifmsh->preq_id, ifmsh);
}

static inline struct ak60211_sta_info *
ak60211_next_hop_deref_protected(struct ak60211_mesh_path *mpath)
{
	return rcu_dereference_protected(mpath->next_hop,
					 lockdep_is_held(&mpath->state_lock));
}

int __ak60211_mpath_queue_preq_new(struct ak60211_if_data *ifmsh, struct hmc_hybrid_path *hmpath, u8 flags)
{
    struct ak60211_mesh_path *mpath;
    struct ak60211_mesh_preq_queue *preq_node;
    u8 *target_addr = hmpath->dst;

    PLC_TRACE();
    mpath = ak60211_mpath_lookup(ifmsh, target_addr);
    if (!mpath) {
        mpath = ak60211_mpath_add(ifmsh, target_addr);
        if (IS_ERR(mpath)) {
            /* mesh_path_discard_frame*/;
            plc_err("is_err\n");
            return PTR_ERR(mpath);
        }
    }

    preq_node = kmalloc(sizeof(struct ak60211_mesh_preq_queue), GFP_ATOMIC);
    if (!preq_node) {
        plc_err("alloc preq_node fail\n");
        return false;
    }

    spin_lock_bh(&ifmsh->mesh_preq_queue_lock);
    if (ifmsh->preq_queue_len == MAX_PREQ_QUEUE_LEN) {
        spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);
        kfree(preq_node);
        plc_err("preq_queue full\n");
        return false;
    }

    spin_lock(&mpath->state_lock);
    if (mpath->flags & PLC_MESH_PATH_REQ_QUEUED) {
        spin_unlock(&mpath->state_lock);
        spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);
        kfree(preq_node);
        plc_err("PATH_QUEUED: %d\n", mpath->flags);
        return false;
    }

    mpath->sn = hmpath->sn;
    memcpy(preq_node->dst, mpath->dst, ETH_ALEN);
    preq_node->flags = flags;

    mpath->flags |= PLC_MESH_PATH_REQ_QUEUED;
    spin_unlock(&mpath->state_lock);

    list_add_tail(&preq_node->list, &ifmsh->preq_queue.list);
    ++ifmsh->preq_queue_len;
    spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);

    if (time_after(jiffies, ifmsh->last_preq +
                msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPpreqMinInterval))) {
        queue_work(ifmsh->workqueue, &ifmsh->work);
    } else if (time_before(jiffies, ifmsh->last_preq)) {
        ifmsh->last_preq = jiffies - msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPpreqMinInterval) - 1;
        queue_work(ifmsh->workqueue, &ifmsh->work);
    } else {
        mod_timer(&ifmsh->mesh_path_timer, ifmsh->last_preq + msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPpreqMinInterval));
    }

    return true;
}


static u32 ak60211_plc_link_metric_get(struct ak60211_sta_info *sta)
{
    return 10;
}

static u32 ak60211_hwmp_route_info_get(struct ak60211_if_data *ifmsh, struct plc_packet_union *buff, enum ak60211_mpath_frame_type action)
{
    struct ak60211_sta_info *sta;
    struct ak60211_mesh_path *mpath;
    bool fresh_info;
    const u8 *orig_addr;
    u32 orig_sn, orig_metric;
    unsigned long orig_lifetime, exp_time;
    u32 last_hop_metric, new_metric;
    bool process = true;
    u8 hopcount;

    rcu_read_lock();
    sta = mesh_info(ifmsh, buff->plchdr.machdr.h_addr2);
    if (!sta) {
        rcu_read_unlock();
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
            rcu_read_unlock();
            return 0;
    }

    new_metric = orig_metric + last_hop_metric;
    if (new_metric < orig_metric) {
        new_metric = MAX_METRIC;
    }
    exp_time = TU_TO_EXP_TIME(orig_lifetime);

    if (ether_addr_equal(orig_addr, ifmsh->addr)) {
        process = false;
        fresh_info = false;
    } else {
        mpath = ak60211_mpath_lookup(ifmsh, orig_addr);
        if (mpath) {
            spin_lock_bh(&mpath->state_lock);
            if (mpath->flags & PLC_MESH_PATH_FIXED) {
                fresh_info = false;
            } else if (mpath->flags & PLC_MESH_PATH_ACTIVE) {
                if (SN_GT(mpath->sn, orig_sn) ||
                        (mpath->sn == orig_sn &&
                        (rcu_access_pointer(mpath->next_hop) != 
                         sta ? mult_frac(new_metric, 10, 9) : 
                         new_metric) >= mpath->metric)) {
                    process = false;
                    fresh_info = false;
                }       
            }
        } else {
            mpath = ak60211_mpath_add(ifmsh, orig_addr);
            if (!mpath) {
                return 0;
            }
            spin_lock_bh(&mpath->state_lock);
        }

        if (fresh_info) {
            /* todo: fresh_info for originator frame and transmitter frame */
            rcu_assign_pointer(mpath->next_hop, sta);
            mpath->flags |= PLC_MESH_PATH_SN_VALID;
            mpath->metric = new_metric;
            mpath->sn = orig_sn;
            mpath->exp_time = time_after(mpath->exp_time, exp_time)? mpath->exp_time : exp_time;
            mpath->hop_count = hopcount;
            mpath->flags |= PLC_MESH_PATH_ACTIVE | PLC_MESH_PATH_RESOLVED;
            spin_unlock_bh(&mpath->state_lock);
            /* todo: ewma_mesh_fail_avg */

            /* information for BR-HMC */
            memcpy(plc->path->dst, mpath->dst, ETH_ALEN);
            plc->path->flags = mpath->flags;
            plc->path->sn = mpath->sn;
            plc->path->metric = mpath->metric;
            plc_debug("flags:0x%x, sn:0x%x, metric:0x%x\n", plc->path->flags, plc->path->sn, plc->path->metric);
            br_hmc_path_update(plc);
        } else {
            spin_unlock_bh(&mpath->state_lock);
        }
    }

    rcu_read_unlock();
    /* todo: Update and check transmitter routing info */
    return process? new_metric : 0;
}

static void ak60211_hwmp_prep_frame_process(struct ak60211_if_data *ifmsh, struct plc_packet_union *buff, u32 metric)
{
    struct ak60211_mesh_path *mpath = NULL;
    const u8 *target_addr, *orig_addr;
    u8 ttl, hopcount, flags;
    u8 next_hop[ETH_ALEN];
    u32 target_sn, orig_sn, lifetime;

    target_addr = buff->un.prep.elem.h_targetaddr;
    orig_addr = buff->un.prep.elem.h_origaddr;
    target_sn = buff->un.prep.elem.target_sn;
    orig_sn = buff->un.prep.elem.orig_sn;

    plc_info("received PREP from %pM\n", target_addr);

    if (ether_addr_equal(orig_addr, ifmsh->addr)) {
        /* destination, no forwarding required */
        return;
    }

    ttl = buff->un.prep.elem.ttl;
    if (ttl <= 1) {
        plc_info("ttl <= 1, dropped frame\n");
        return;
    }

    mpath = ak60211_mpath_lookup(ifmsh, orig_addr);
    if (!mpath) {
        return;
    }

    memcpy(next_hop, ak60211_next_hop_deref_protected(mpath)->addr, ETH_ALEN);
    --ttl;
    flags = buff->un.prep.elem.flags;
    lifetime = buff->un.prep.elem.lifetime;
    hopcount = buff->un.prep.elem.hop_count;

    ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREP, flags, orig_addr, orig_sn, target_addr, target_sn, buff->sa, 
                                       0, ttl, lifetime, metric, 0, ifmsh);
}

static void ak60211_hwmp_preq_frame_process(struct ak60211_if_data *ifmsh, struct plc_packet_union *buff, u32 orig_metric)
{
    struct ak60211_mesh_path *mpath = NULL;
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

    plc_info("received PREQ from %pM\n", orig_addr);

    if (ether_addr_equal(target_addr, ifmsh->addr)) {
        plc_info("PREQ is for us\n");
        forward = false;
        reply = true;
        target_metric = 0;

        if (SN_GT(target_sn, ifmsh->sn)) {
            ifmsh->sn = target_sn;
        }

        if (time_after(jiffies, ifmsh->last_sn_update + 
                   msecs_to_jiffies(MESH_TRAVERSAL_TIME)) || 
                time_before(jiffies, ifmsh->last_sn_update)) {
            ifmsh->sn++;
            ifmsh->last_sn_update = jiffies;
        }

        target_sn = ifmsh->sn;
    } else if (is_broadcast_ether_addr(target_addr)) {
        /* target only and broadcast will go in here */
        rcu_read_lock();
        mpath = ak60211_mpath_lookup(ifmsh, orig_addr);
        if (mpath) {
            reply = true;
            target_addr = ifmsh->addr;
            target_sn = ++ifmsh->sn;
            target_metric = 0;
            ifmsh->last_sn_update = jiffies;
        }
        if (root_is_gate) {
            /* todo: mesh_path_add_gate() */
        }
        rcu_read_unlock();
    } else {
        rcu_read_lock();
        mpath = ak60211_mpath_lookup(ifmsh, target_addr);
        if (mpath) {
            if (SN_LT(mpath->sn, target_sn)) {
                mpath->sn = target_sn;
                mpath->flags |= PLC_MESH_PATH_SN_VALID;
            }
        }
        rcu_read_unlock();
    }

    if (reply) {
        lifetime = buff->un.preq.elem.lifetime;
        ttl = MAX_MESH_TTL;
        if (ttl != 0) {
            plc_info("replying to the PREQ\n");
            ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREP, 0, orig_addr, orig_sn, target_addr, target_sn, buff->sa, 
                                       0, ttl, lifetime, target_metric, 0, ifmsh);

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

        plc_info("forwarding the PREQ from %pM\n", orig_addr);
        --ttl;
        preq_id = buff->un.preq.elem.preq_id;
        hopcount = buff->un.preq.elem.hop_count + 1;
        da = (mpath && mpath->is_root)? broadcast_addr : broadcast_addr;/*mpath->rann_snd_addr : broadcast_addr;*/

        ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREQ, flags, orig_addr, orig_sn, target_addr, target_sn, da, 
                                   hopcount, ttl, lifetime, orig_metric, preq_id, ifmsh);
    }
}

void ak60211_mesh_rx_path_sel_frame(struct ak60211_if_data *ifmsh, struct plc_packet_union *buff)
{
    u32 path_metric;
    struct ak60211_sta_info *sta;
    enum ieee80211_eid tag = buff->un.preq.elem.tag;

    sta = mesh_info(ifmsh, buff->plchdr.machdr.h_addr2);
    if (!sta || sta->plink_state != AK60211_PLINK_ESTAB) {
        plc_err("no sta %pM info or sta->plink_state != ESTAB\n", buff->plchdr.machdr.h_addr2);
        return;
    }

    switch(tag) {
        case WLAN_EID_PREQ:
            if (buff->un.preq.elem.len != 37) {
                plc_err("preq elem len is not 37\n");
                return;
            }
            path_metric = ak60211_hwmp_route_info_get(ifmsh, buff, AK60211_MPATH_PREQ);

            if (path_metric) {
                ak60211_hwmp_preq_frame_process(ifmsh, buff, path_metric);
            }
            break;
        case WLAN_EID_PREP:
            if (buff->un.prep.elem.len != 31) {
                plc_err("prep elem len is not 31\n");
                return;
            }

            path_metric = ak60211_hwmp_route_info_get(ifmsh, buff, AK60211_MPATH_PREP);

            if (path_metric) {
                ak60211_hwmp_prep_frame_process(ifmsh, buff, path_metric);
            }
            break;
        default:
            plc_err("tag not found\n");
            break;
    }
}


void ak60211_mpath_start_discovery(struct ak60211_if_data *ifmsh)
{
    struct ak60211_mesh_preq_queue *preq_node;
    struct ak60211_mesh_path *mpath;
    u8 ttl, target_flags = 0;
    const u8 *da;
    u32 lifetime;

    PLC_TRACE();

    /* preq queue is nothing or time period is smaller than min interval */
    spin_lock_bh(&ifmsh->mesh_preq_queue_lock);
    if (!ifmsh->preq_queue_len || 
            time_before(jiffies, ifmsh->last_preq + 
                msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPpreqMinInterval))) {
        spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);
        return;
    }

    preq_node = list_first_entry(&ifmsh->preq_queue.list, 
            struct ak60211_mesh_preq_queue, list);
    list_del(&preq_node->list);
    --ifmsh->preq_queue_len;
    spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);

    rcu_read_lock();
    mpath = ak60211_mpath_lookup(ifmsh, preq_node->dst);
    if (!mpath) {
        plc_err("mpath lookup fail\n");
        goto enddiscovery;
    }

    spin_lock_bh(&mpath->state_lock);
    if (mpath->flags & (PLC_MESH_PATH_DELETED | PLC_MESH_PATH_FIXED)) {
        spin_unlock_bh(&mpath->state_lock);
        goto enddiscovery;
    }
    mpath->flags &= ~PLC_MESH_PATH_REQ_QUEUED;
    if (preq_node->flags & AK60211_PREQ_START) {
        if (mpath->flags & PLC_MESH_PATH_RESOLVING) {
            spin_unlock_bh(&mpath->state_lock);
            goto enddiscovery;
        } else {
            mpath->flags &= ~PLC_MESH_PATH_RESOLVED;
            mpath->flags |= PLC_MESH_PATH_RESOLVING;
            mpath->discovery_retries = 0;
            mpath->discovery_timeout = msecs_to_jiffies(ifmsh->mshcfg.min_discovery_timeout);
        }
    } else if (!(mpath->flags & PLC_MESH_PATH_RESOLVING) || 
            mpath->flags & PLC_MESH_PATH_RESOLVED) {
        mpath->flags &= ~PLC_MESH_PATH_RESOLVING;
        spin_unlock_bh(&mpath->state_lock);
        goto enddiscovery;
    }

    ifmsh->last_preq = jiffies;

    if (time_after(jiffies, ifmsh->last_sn_update +
                msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPnetDiameterTraversalTime)) ||
            time_before(jiffies, ifmsh->last_sn_update)) {
        ++ifmsh->sn;
        ifmsh->last_sn_update = jiffies;
    }
    lifetime = MSEC_TO_TU(ifmsh->mshcfg.MeshHWMPactivePathTimeout);
    ttl = ifmsh->mshcfg.element_ttl;
    if (ttl == 0) {
        goto enddiscovery;
    }

    if (preq_node->flags & AK60211_PREQ_REFRESH) {
        target_flags |= IEEE80211_PREQ_TO_FLAG;
    } else {
        target_flags &= ~IEEE80211_PREQ_TO_FLAG;
    }

    spin_unlock_bh(&mpath->state_lock);
    da = broadcast_addr;

    memcpy(plc->path->dst, mpath->dst, ETH_ALEN);
    plc->path->flags = mpath->flags;
    plc->path->sn = mpath->sn;
    plc->path->metric = MAX_METRIC;
    plc_debug("flags:0x%x, sn:0x%x, metric:0x%x\n", plc->path->flags, plc->path->sn, plc->path->metric);
    br_hmc_path_update(plc);

    ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREQ, 0, ifmsh->addr, ifmsh->sn, mpath->dst,
                    mpath->sn, da, 0, ttl, lifetime, 0, ifmsh->preq_id++, ifmsh);
    
    spin_lock_bh(&mpath->state_lock);
    if (mpath->flags & PLC_MESH_PATH_DELETED) {
        spin_unlock_bh(&mpath->state_lock);
        goto enddiscovery;
    }
    mod_timer(&mpath->timer, jiffies + mpath->discovery_timeout);
    spin_unlock_bh(&mpath->state_lock);

enddiscovery:
    rcu_read_unlock();
    kfree(preq_node);
}

static bool ak60211_llid_in_use(struct ak60211_if_data *local, u16 llid)
{
    bool in_use = false;
    struct ak60211_sta_info *sta;

    rcu_read_lock();
    list_for_each_entry_rcu(sta, &local->sta_list, list) {
        if (local != sta->local) {
            continue;
        }

        if (!memcmp(&sta->llid, &llid, sizeof(llid))) {
            in_use = true;
            break;
        }
    }

    rcu_read_unlock();

    return in_use;
}

static u16 ak60211_mesh_get_new_llid(struct ak60211_if_data *local)
{
    u16 llid;

    do {
        get_random_bytes(&llid, sizeof(llid));
    } while(ak60211_llid_in_use(local, llid));

    return llid;
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
    plc_info("Mesh plink with %pM ESTABLISHED\n", sta->addr);
}

int ak60211_mesh_match_local(struct meshprofhdr *peer)
{
    if (!(peer->meshid_elem.elemid == local_prof.meshid_elem.elemid &&
        peer->meshid_elem.len == local_prof.meshid_elem.len &&
        !memcmp(peer->meshid_elem.meshid, local_prof.meshid_elem.meshid, MAX_MESH_ID_LEN) &&
        peer->meshconf_elem.psel_protocol == local_prof.meshconf_elem.psel_protocol &&
        peer->meshconf_elem.psel_metric == local_prof.meshconf_elem.psel_metric &&
        peer->meshconf_elem.congestion_ctrl_mode == local_prof.meshconf_elem.congestion_ctrl_mode &&
        peer->meshconf_elem.sync_method == local_prof.meshconf_elem.sync_method &&
        peer->meshconf_elem.auth_protocol == local_prof.meshconf_elem.auth_protocol )) {
        plc_err("mesh do not match!!\n");
        return false;
    }

    return true;
}

static inline void ak60211_mesh_plink_timer_set(struct ak60211_sta_info *sta, u32 timeout)
{
    sta->plink_timeout = timeout;
    mod_timer(&sta->plink_timer, jiffies + msecs_to_jiffies(timeout));
}

static void ak60211_mesh_plink_open(struct ak60211_sta_info *sta, struct plc_packet_union *buff)
{
    PLC_TRACE();
    sta->llid = ak60211_mesh_get_new_llid(sta->local);
    if (sta->plink_state != AK60211_PLINK_LISTEN) {
        return;
    }

    sta->plink_state = AK60211_PLINK_OPN_SNT;
    // todo: add timeout function ak60211_mesh_plink_timer_set(sta, AK60211_MESH_RETRY_TIMEOUT);

    plc_info("Mesh plink: start estab with %pM\n", sta->addr);

    ak60211_mesh_plink_frame_tx(sta->local, WLAN_SP_MESH_PEERING_OPEN, buff->plchdr.machdr.h_addr4, sta->llid, 0);
}

void ak60211_mesh_neighbour_update(struct ak60211_if_data *ifmsh, struct plc_packet_union *buff)
{
    struct ak60211_sta_info *sta;

    sta = mesh_sta_info_get(ifmsh, buff->plchdr.machdr.h_addr4);

    if(!sta) {
        plc_err("mesh sta info get fail\n");
        goto out;
    }
    if (sta->plink_state == AK60211_PLINK_LISTEN) {
        ak60211_mesh_plink_open(sta, buff);
    }
out:
    return;
}


static enum ak60211_plink_event ak60211_plink_get_event(struct ak60211_if_data *ifmsh, u16 ftype, u16 plid, u16 llid, 
                            struct plc_packet_union *buff, struct ak60211_sta_info *sta)
{
    enum ak60211_plink_event event = PLINK_UNDEFINED;
    bool matches_local;
    struct meshprofhdr peer;

    PLC_TRACE();

    memcpy(&peer.meshid_elem, &buff->un.self.meshid_elem, sizeof(struct meshidhdr));
    memcpy(&peer.meshconf_elem, &buff->un.self.meshconf_elem, sizeof(struct meshconfhdr));

    matches_local = ak60211_mesh_match_local(&peer);

    if (!matches_local && !sta) {
        event = OPN_RJCT;
        goto out;
    }

    if (!sta) {
        if (ftype != WLAN_SP_MESH_PEERING_OPEN) {
            plc_err("Mesh plink: cls or cnf from unknown peer\n");
            goto out;
        }

       if (!ak60211_mplink_free_count(ifmsh)) {
           plc_err("Mesh plink: no more free plinks\n");
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
            if (!ak60211_mplink_free_count(ifmsh) ||
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
            if (!ak60211_mplink_free_count(ifmsh) ||
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

static void ak60211_mesh_plink_fsm(enum ak60211_plink_event event, struct ak60211_sta_info *sta, struct plc_packet_union *buff)
{
    enum ieee80211_self_protected_actioncode action = 0;

    PLC_TRACE();
    plc_info("peer %pM in state %s got events %s\n", sta->addr, mplstates[sta->plink_state], mplevents[event]);

    switch(sta->plink_state) {
        case AK60211_PLINK_LISTEN:
            switch (event) {
                case CLS_ACPT:
                    ak60211_mesh_plink_fsm_restart(sta);
                    break;
                case OPN_ACPT:
                    sta->plink_state = AK60211_PLINK_OPN_RCVD;
                    sta->llid = ak60211_mesh_get_new_llid(sta->local);

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
        ak60211_mesh_plink_frame_tx(sta->local, action, buff->plchdr.machdr.h_addr4, sta->llid, sta->plid);

        if (action == WLAN_SP_MESH_PEERING_OPEN) {
            ak60211_mesh_plink_frame_tx(sta->local, WLAN_SP_MESH_PEERING_CONFIRM, buff->plchdr.machdr.h_addr4, sta->llid, sta->plid);
        }
    }
}

void ak60211_mesh_rx_plink_frame(struct ak60211_if_data *ifmsh, struct plc_packet_union *buff)
{    
    struct ak60211_sta_info *sta;
    u16 ftype;
    u16 plid, llid = 0;
    enum ak60211_plink_event event;

    ftype = buff->un.self.action;
    if (is_multicast_ether_addr(buff->da)) {
        plc_err("Mesh plink: ignore frame from multicast\n");
        return;
    }

    plid = get_unaligned_le16(&buff->un.self.mpm_elem.llid);
    if (ftype == WLAN_SP_MESH_PEERING_CONFIRM) {
        llid = get_unaligned_le16(&buff->un.self.mpm_elem.plid);
    }

    sta = mesh_info(ifmsh, buff->plchdr.machdr.h_addr4);

    // todo: check rssi threshold
    
    event = ak60211_plink_get_event(ifmsh, ftype, plid, llid, buff, sta);

    if (event == OPN_ACPT) {
        sta = mesh_sta_info_get(ifmsh, buff->plchdr.machdr.h_addr4);
        if (!sta) {
            plc_err("Mesh plink: failed to init peer!\n");
        }
        sta->plid = plid;
    } else if (!sta && event == OPN_RJCT) {
        ak60211_mesh_plink_frame_tx(ifmsh, WLAN_SP_MESH_PEERING_OPEN, buff->plchdr.machdr.h_addr4, 0, plid);
    }

    if (event == CNF_ACPT) {
        if (!sta->plid) {
            sta->plid = plid;
        }
    }

    ak60211_mesh_plink_fsm(event, sta, buff);
}
