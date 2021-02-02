#include "mac60211.h"
#include "ak60211_mesh_private.h"

static u32 ak60211_mtbl_hash(const void *addr, u32 len, u32 seed)
{
    return jhash_1word(__get_unaligned_cpu32((u8 *)addr + 2), seed);
}

static const struct rhashtable_params ak60211_mesh_rht_params = {
    .nelem_hint = 2,
    .automatic_shrinking = true,
    .key_len = ETH_ALEN,
    .key_offset = offsetof(struct ak60211_mesh_path, dst),
    .head_offset = offsetof(struct ak60211_mesh_path, rhash),
    .hashfn = ak60211_mtbl_hash,
};

static inline bool ak60211_mpath_expired(struct ak60211_mesh_path *mpath)
{
    return (mpath->flags & PLC_MESH_PATH_ACTIVE) &&
            time_after(jiffies, mpath->exp_time) &&
            !(mpath->flags & PLC_MESH_PATH_FIXED);
}

inline bool ak60211_mplink_availables(struct ak60211_if_data *ifmsh)
{
    int freecnt = ifmsh->mshcfg.MeshMaxPeerLinks - 
                    atomic_read(&ifmsh->estab_plinks);
    
    return (min_t(long, freecnt, MESH_MAX_PLINKS - ifmsh->num_sta)) > 0;
}

static struct rhlist_head *ak60211_sta_info_hash_lookup(struct ak60211_if_data *local, const u8 *addr)
{
    return rhltable_lookup(&local->sta_hash, addr, ak60211_sta_rht_params);
}

struct ak60211_sta_info* mesh_info(struct ak60211_if_data *ifmsh, u8 *addr)
{
    struct ak60211_sta_info* sta = NULL;
    struct rhlist_head *tmp;
    rcu_read_lock();
    rhl_for_each_entry_rcu(sta, tmp, ak60211_sta_info_hash_lookup(ifmsh, addr), hash_node) {
        rcu_read_unlock();
        return sta;
    }

    rcu_read_unlock();
    return NULL;
}

static void ak60211_mesh_sta_init(struct ak60211_sta_info *sta)
{
    if (sta->plink_state == AK60211_PLINK_ESTAB &&
            sta->processed_beacon) {
        return;
    }
    sta->processed_beacon = true;
}

static int ak60211_sta_info_hash_add(struct ak60211_if_data *local, struct ak60211_sta_info *sta)
{
    return rhltable_insert(&local->sta_hash, &sta->hash_node, ak60211_sta_rht_params);
}

static void ak60211_mplinks_update(struct ak60211_if_data *ifmsh)
{
    bool free_plinks;

    free_plinks = ak60211_mplink_availables(ifmsh);
    ifmsh->accepting_plinks = free_plinks;
}

static int ak60211_sta_info_insert_finish(struct ak60211_sta_info *sta)
{
    struct ak60211_if_data *local = sta->local;
    int err = 0;

    lockdep_assert_held(&local->sta_mtx);

    /* check if STA exists already */
    if (mesh_info(local, sta->addr)) {
        err = -EEXIST;
        plc_err("STA %pM exists already\n", sta->addr);
        goto out_err;
    }

    local->num_sta++;
    local->sta_generation++;

    err = ak60211_sta_info_hash_add(local, sta);
    if (err) {
        plc_err("STA %pM hash add fail\n", sta->addr);
        goto out_drop_sta;
    }

    list_add_tail_rcu(&sta->list, &local->sta_list);

    plc_info("Inserted STA %pM\n", sta->addr);
    mutex_unlock(&local->sta_mtx);

    ak60211_mplinks_update(local);
    return 0;

out_drop_sta:
    local->num_sta--;
    /* __cleanup_single_sta */
out_err:
    mutex_unlock(&local->sta_mtx);
    return err;
}

static int ak60211_sta_info_insert_check(struct ak60211_sta_info *sta)
{
    struct ak60211_if_data *local = sta->local;

    if (WARN_ON(ether_addr_equal(sta->addr, local->addr) || 
                is_multicast_ether_addr(sta->addr))) {
        return -EINVAL;
    }

    return 0;
}

static void ak60211_sta_info_free(struct ak60211_if_data *local, struct ak60211_sta_info *sta)
{
    plc_info("Destroyed STA %pM\n", sta->addr);

    kfree(sta);
}

static int ak60211_sta_info_insert(struct ak60211_sta_info *sta)
{
    struct ak60211_if_data *local = sta->local;
    int err;
    mutex_lock(&local->sta_mtx);

    err = ak60211_sta_info_insert_check(sta);
    if (err) {
        mutex_unlock(&local->sta_mtx);
        goto out_free;
    }

    err = ak60211_sta_info_insert_finish(sta);
    if (err) {
        goto out_free;
    }

    return 0;
out_free:
    ak60211_sta_info_free(local, sta);
    return err;
}

struct ak60211_sta_info* mesh_sta_info_get(struct ak60211_if_data *ifmsh, u8 *addr)
{
    struct ak60211_sta_info* sta = mesh_info(ifmsh, addr);
    
    if (sta) {
        ak60211_mesh_sta_init(sta);
    } else {
        plc_info("sta is not exist, alloc new sta\n");
        sta = ak60211_mesh_sta_alloc(ifmsh, addr);

        if (!sta) {
            plc_err("mesh sta alloc fail\n");
            return NULL;
        }

        ak60211_mesh_sta_init(sta);

        /* todo: sta_info_insert_rcu */
        if(ak60211_sta_info_insert(sta)) {
            return NULL;
        }
         
    }

    return sta;
}

static void ak60211_mpath_free_rcu(struct ak60211_mesh_table *tbl, struct ak60211_mesh_path *mpath)
{
    struct ak60211_if_data *ifmsh = mpath->sdata;

    spin_lock_bh(&mpath->state_lock);
    mpath->flags |= PLC_MESH_PATH_RESOLVING | PLC_MESH_PATH_DELETED;
    spin_unlock_bh(&mpath->state_lock);
    del_timer_sync(&mpath->timer);
    atomic_dec(&ifmsh->mpaths);
    atomic_dec(&tbl->entries);
    kfree_rcu(mpath, rcu);
}

static void __ak60211_mpath_del(struct ak60211_mesh_table *tbl, struct ak60211_mesh_path *mpath)
{
    PLC_TRACE();

    memcpy(plc->path->dst, mpath->dst, ETH_ALEN);
    plc->path->flags = 0;
    plc->path->sn = 0;//mpath->sn;
    plc->path->metric = 0;//MAX_METRIC;
    plc_debug("mpath del, inform br-hmc to update status\n");
    br_hmc_path_update(plc);

    hlist_del_rcu(&mpath->walk_list);
    rhashtable_remove_fast(&tbl->rhead, &mpath->rhash, ak60211_mesh_rht_params);
    ak60211_mpath_free_rcu(tbl, mpath);
}

void ak60211_mtbl_expire(struct ak60211_if_data *ifmsh)
{
    struct ak60211_mesh_path *mpath;
    struct hlist_node *n;
    struct ak60211_mesh_table *tbl = ifmsh->mesh_paths;

    spin_lock_bh(&tbl->walk_lock);
    
    hlist_for_each_entry_safe(mpath, n, &tbl->walk_head, walk_list) {
        if ((!(mpath->flags & PLC_MESH_PATH_RESOLVING)) &&
            (!(mpath->flags & PLC_MESH_PATH_FIXED)) &&
             time_after(jiffies, mpath->exp_time + MESH_PATH_EXPIRE)) {
            __ak60211_mpath_del(tbl, mpath);
        }
    }
    
    spin_unlock_bh(&tbl->walk_lock);
}

/*void ak60211_mplink_timer(struct timer_list *t)
{
    struct ak60211_sta_info *sta = from_timer(sta, t, plink_timer);

    spin_lock_bh(&sta->plink_lock);



}*/

static struct ak60211_sta_info *__ak60211_mesh_sta_alloc(struct ak60211_if_data *ifmsh, u8 *addr)
{
    struct ak60211_sta_info *sta;

    if (ifmsh->num_sta >= MESH_MAX_PLINKS) {
        return NULL;
    }

    sta = kzalloc(sizeof(struct ak60211_sta_info), GFP_KERNEL);
    if (!sta) {
        return NULL;
    }

    /* todo: need to check sta plink timer
    spin_lock_init(&sta->plink_lock);
    timer_setup(&sta->plink_timer, ak60211_mplink_timer, 0);
    */
    memcpy(sta->addr, addr, ETH_ALEN);
    sta->local = ifmsh;

    /*
     * todo: ewma_signal init & ewma_avg_signal_init
     * */
    sta->plink_state = AK60211_PLINK_LISTEN;

    /*
     * todo: sta_info_pre_move_state(STA_AUTH, STA_ASSOC, STA_AUTHORIZED)
     * */

    plc_debug("Allocated STA %pM\n", sta->addr);
    return sta;
}

struct ak60211_sta_info* ak60211_mesh_sta_alloc(struct ak60211_if_data *ifmsh, u8 *addr)
{
    struct ak60211_sta_info *sta = NULL;
    
    if (0) {
        /* if security is using */
        if (ak60211_mplink_availables(ifmsh)) {
            ;
        }
    } else {
        sta = __ak60211_mesh_sta_alloc(ifmsh, addr);
        if (!sta) {
            return NULL;
        }
    }

    return sta;
}

static struct ak60211_mesh_table *ak60211_mtbl_alloc(void)
{
    struct ak60211_mesh_table *newtbl;

    newtbl = kmalloc(sizeof(struct ak60211_mesh_table), GFP_ATOMIC);
    if (!newtbl) {
        return NULL;
    }

    INIT_HLIST_HEAD(&newtbl->walk_head);
    atomic_set(&newtbl->entries, 0);
    spin_lock_init(&newtbl->walk_lock);

    return newtbl;
}

void ak60211_mpath_timer(struct timer_list *t)
{
    struct ak60211_mesh_path *mpath = from_timer(mpath, t, timer);
    struct ak60211_if_data *ifmsh = mpath->sdata;

    PLC_TRACE();
    spin_lock_bh(&mpath->state_lock);
    if (mpath->flags & PLC_MESH_PATH_RESOLVED ||
            (!(mpath->flags & PLC_MESH_PATH_RESOLVING))) {
        mpath->flags &= ~(PLC_MESH_PATH_RESOLVING | PLC_MESH_PATH_RESOLVING);
        spin_unlock_bh(&mpath->state_lock);
    } else if (mpath->discovery_retries < ifmsh->mshcfg.MeshHWMPmaxPREQretries) {
        struct hmc_hybrid_path hmpath;
        memcpy(hmpath.dst, mpath->dst, ETH_ALEN);
        hmpath.sn = mpath->sn;
        ++mpath->discovery_retries;
        mpath->discovery_timeout *= 2;
        mpath->flags &= ~PLC_MESH_PATH_REQ_QUEUED;
        spin_unlock_bh(&mpath->state_lock);
        __ak60211_mpath_queue_preq_new(ifmsh, &hmpath, 0);
    } else {
        mpath->flags &= ~(PLC_MESH_PATH_RESOLVING |
                    PLC_MESH_PATH_RESOLVED | PLC_MESH_PATH_REQ_QUEUED);
        mpath->exp_time = jiffies;

        memcpy(plc->path->dst, mpath->dst, ETH_ALEN);
        plc->path->flags = mpath->flags;
        plc->path->sn = mpath->sn;
        plc->path->metric = MAX_METRIC;
        plc_debug("mpath discovery retry max, stop send preq\n");
        br_hmc_path_update(plc);
        spin_unlock_bh(&mpath->state_lock);
    }
}

static struct ak60211_mesh_path *ak60211_mpath_new(struct ak60211_if_data *ifmsh, const u8 *dst, gfp_t gfp)
{
    struct ak60211_mesh_path *new_mpath;

    new_mpath = kzalloc(sizeof(struct ak60211_mesh_path), gfp);
    if (!new_mpath) {
        return NULL;
    }

    memcpy(new_mpath->dst, dst, ETH_ALEN);
    //eth_broadcast_addr(broadcast_addr);
    new_mpath->is_root = false;
    new_mpath->sdata = ifmsh;
    new_mpath->flags = 0;
    new_mpath->exp_time = jiffies;
    spin_lock_init(&new_mpath->state_lock);
    timer_setup(&new_mpath->timer, ak60211_mpath_timer, 0);

    return new_mpath;
}

struct ak60211_mesh_path *ak60211_mpath_add(struct ak60211_if_data *ifmsh, const u8 *dst)
{
    struct ak60211_mesh_path *new_mpath = NULL, *mpath;
    struct ak60211_mesh_table *tbl;

    if (ether_addr_equal(dst, ifmsh->addr)) {
        plc_err("dst is equal to us no support\n");
        return false;
    }

    if (is_multicast_ether_addr(dst)) {
        plc_err("dst is multicast no support\n");
        return false;
    }

    if (atomic_add_unless(&ifmsh->mpaths, 1, MESH_MAX_PATHS) == 0) {
        plc_err("mpath is no free available\n");
        return false;
    }

    new_mpath = ak60211_mpath_new(ifmsh, dst, GFP_ATOMIC);
    if (!new_mpath) {
        plc_err("mpath allocate fail\n");
        return false;
    }

    tbl = ifmsh->mesh_paths;
    spin_lock_bh(&tbl->walk_lock);
    mpath = rhashtable_lookup_get_insert_fast(&tbl->rhead, &new_mpath->rhash, ak60211_mesh_rht_params);
    if (!mpath) {
        hlist_add_head(&new_mpath->walk_list, &tbl->walk_head);
    }
    spin_unlock_bh(&tbl->walk_lock);

    if (mpath) {
        kfree(new_mpath);

        if (IS_ERR(mpath)) {
            return mpath;
        }

        new_mpath = mpath;
    }

    ifmsh->mesh_paths_generations++;
    return new_mpath;
}

struct ak60211_mesh_path *ak60211_mpath_lookup(struct ak60211_if_data *ifmsh, const u8 *dst)
{
    struct ak60211_mesh_path *mpath;
    struct ak60211_mesh_table *tbl = ifmsh->mesh_paths;

    mpath = rhashtable_lookup(&tbl->rhead, dst, ak60211_mesh_rht_params);

    if (mpath && ak60211_mpath_expired(mpath)) {
        spin_lock_bh(&mpath->state_lock);
        mpath->flags &= ~PLC_MESH_PATH_ACTIVE;
        spin_unlock_bh(&mpath->state_lock);
    }

    return mpath;
}

static void ak60211_mpath_rht_free(void *ptr, void *tblptr)
{
    struct ak60211_mesh_path *mpath = ptr;
    struct ak60211_mesh_table *tbl = tblptr;

    ak60211_mpath_free_rcu(tbl, mpath);
}

static void ak60211_mtbl_free(struct ak60211_mesh_table *tbl)
{
    rhashtable_free_and_destroy(&tbl->rhead, ak60211_mpath_rht_free, tbl);

    kfree(tbl);
}

int ak60211_mpath_tbl_init(struct ak60211_if_data *ifmsh)
{
    struct ak60211_mesh_table *tbl_path;

    tbl_path = ak60211_mtbl_alloc();
    if (!tbl_path) {
        return -ENOMEM;
    }

    rhashtable_init(&tbl_path->rhead, &ak60211_mesh_rht_params);
    ifmsh->mesh_paths = tbl_path;

    return 0;
}

void ak60211_mtbl_deinit(struct ak60211_if_data *ifmsh)
{
    PLC_TRACE();
    ak60211_mtbl_free(ifmsh->mesh_paths);
}

