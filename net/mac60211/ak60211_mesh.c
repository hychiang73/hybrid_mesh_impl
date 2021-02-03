#include <ak60211_mesh_private.h>
#include <mac60211.h>
#include <nl60211.h>

#define MESH_TTL		31
#define MESH_DEFAULT_ELEMENT_TTL 31
#define MESH_MAX_RETR	3
#define MESH_RET_T		100
#define MESH_CONF_T		100
#define MESH_HOLD_T		100

#define MESH_PATH_TIMEOUT	5000
#define MESH_DEFAULT_PLINK_TIMEOUT	1800 /* timeout in seconds */

/* Minimum interval between two consecutive PREQs originated
 * by the same interface
 */
#define MESH_PREQ_MIN_INT	10
#define MESH_PERR_MIN_INT	100
#define MESH_DIAM_TRAVERSAL_TIME 50

#define MESH_RSSI_THRESHOLD	0

/* A path will be refreshed if it is used PATH_REFRESH_TIME milliseconds
 * before timing out.  This way it will remain ACTIVE and no data frames
 * will be unnecessarily held in the pending queue.
 */
#define MESH_PATH_REFRESH_TIME			1000
#define MESH_MIN_DISCOVERY_TIMEOUT (2 * MESH_DIAM_TRAVERSAL_TIME)

/* Default maximum number of established plinks per interface */
#define MESH_MAX_ESTAB_PLINKS	32

#define MESH_MAX_PREQ_RETRIES	4

#define MESH_DEFAULT_BEACON_INTERVAL	1000	/* in 1024 us units (=TUs) */

struct ak60211_if_data plcdev;
const u8 broadcast_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

const struct meshprofhdr local_prof = {
	.meshid_elem.elemid = 114,
	.meshid_elem.len = MAX_MESH_ID_LEN,
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

const struct ak60211_mesh_config default_mesh_config = {
	.MeshRetryTimeout = MESH_RET_T,
	.MeshConfirmTimeout = MESH_CONF_T,
	.MeshHoldingTimeout = MESH_HOLD_T,
	.MeshMaxRetries = MESH_MAX_RETR,
	.MeshTTL = MESH_TTL,
	.element_ttl = MESH_DEFAULT_ELEMENT_TTL,
	.MeshMaxPeerLinks = MESH_MAX_ESTAB_PLINKS,
	.MeshHWMPactivePathTimeout = MESH_PATH_TIMEOUT,
	.MeshHWMPpreqMinInterval = MESH_PREQ_MIN_INT,
	.MeshHWMPperrMinInterval = MESH_PERR_MIN_INT,
	.MeshHWMPnetDiameterTraversalTime = MESH_DIAM_TRAVERSAL_TIME,
	.MeshHWMPmaxPREQretries = MESH_MAX_PREQ_RETRIES,
	.path_refresh_time = MESH_PATH_REFRESH_TIME,
	.min_discovery_timeout = MESH_MIN_DISCOVERY_TIMEOUT,
	.rssi_threshold = MESH_RSSI_THRESHOLD,
	.plink_timeout = MESH_DEFAULT_PLINK_TIMEOUT,
	.beacon_interval = MESH_DEFAULT_BEACON_INTERVAL,
};

const struct rhashtable_params ak60211_sta_rht_params = {
	.nelem_hint = 3, /* start small */
	.automatic_shrinking = true,
	.head_offset = offsetof(struct ak60211_sta_info, hash_node),
	.key_offset = offsetof(struct ak60211_sta_info, addr),
	.key_len = ETH_ALEN,
	//.max_size = CONFIG_MAC80211_STA_HASH_MAX_SIZE,
};

void ak60211_pkt_hex_dump(struct sk_buff *skb, const char *type, int offset)
{
	size_t len;
	int rowsize = 16;
	int i, l, linelen, remaining;
	int li = 0;
	u8 *data, ch;

	if (!plc_dbg)
		return;

	data = (u8 *)skb_mac_header(skb);
   //data = (u8 *) skb->head;

	if (skb_is_nonlinear(skb))
		len = skb->data_len;
	else
		len = skb->len;

	remaining = len + 2 + offset;
	pr_info("Packet hex dump (len = %ld):\n", len);
	pr_info("============== %s ==============\n", type);
	for (i = 0; i < len; i += rowsize) {
		pr_info("%06d\t", li);

		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		for (l = 0; l < linelen; l++) {
			ch = data[l];
			pr_cont("%02X ", (uint32_t)ch);
		}

		data += linelen;
		li += 10;

		pr_cont("\n");
	}
	pr_info("====================================\n");
}

static int __must_check
		__ak60211_sta_info_destroy(struct ak60211_sta_info *sta,
					   struct ak60211_if_data *ifmsh)
{
	int ret;

	// destroy part1
	might_sleep();

	if (!sta)
		return -ENONET;

	lockdep_assert_held(&ifmsh->sta_mtx);

	ret = rhltable_remove(&ifmsh->sta_hash, &sta->hash_node,
			      ak60211_sta_rht_params);
	if (WARN_ON(ret))
		return ret;

	list_del_rcu(&sta->list);

	// destroy part2
	ifmsh->num_sta--;
	ifmsh->sta_generation++;

	plc_info("Removed STA %pM\n", sta->addr);
	kfree(sta);

	return ret;
}

static void ak60211_sta_expire(struct ak60211_if_data *ifmsh,
			       unsigned long exp_time)
{
	struct ak60211_sta_info *sta, *tmp;

	mutex_lock(&ifmsh->sta_mtx);

	list_for_each_entry_safe(sta, tmp, &ifmsh->sta_list, list) {
		unsigned long last_active = 0;
		/* last_active = ieee80211_sta_last_active(sta)
		 * check the sta active status, need to check hw compatible
		 **/

		if (last_active) {
			if (time_is_before_jiffies(last_active + exp_time)) {
				plc_info("expiring inactive STA %pM\n",
					 sta->addr);
				WARN_ON(__ak60211_sta_info_destroy(sta, ifmsh));
			}
		}
	}
	mutex_unlock(&ifmsh->sta_mtx);
}

void ak60211_mesh_plink_frame_tx(struct ak60211_if_data *ifmsh,
				 enum ak60211_sp_actioncode action,
				 u8 *addr, u16 llid, u16 plid)
{
	struct sk_buff *nskb;
	struct ethhdr *ether;
	struct plc_hdr *plchdr;
	u8 *pos;

	/* headroom + ETH header + plchdr + action + fcs + reserved */
	nskb = dev_alloc_skb(2 + ETH_HLEN +
			42 + 79 + 4 + 2);
	if (!nskb)
		return;

	skb_reserve(nskb, 2);
	ether = (struct ethhdr *)skb_put_zero(nskb, ETH_HLEN);
	memcpy(ether->h_dest, addr, ETH_ALEN);
	memcpy(ether->h_source, ifmsh->addr, ETH_ALEN);
	ether->h_proto = ntohs(0xAA55);

	/* plc hdr*/
	plchdr = skb_put_zero(nskb, 42);
	plchdr->framectl = cpu_to_le16(AK60211_FTYPE_MGMT |
						 AK60211_STYPE_ACTION);

	plchdr->duration_id = 0;

	memcpy(plchdr->machdr.h_addr1, addr, 6);
	memcpy(plchdr->machdr.h_addr3, addr, 6);
	memcpy(plchdr->machdr.h_addr2, ifmsh->addr, 6);
	memcpy(plchdr->machdr.h_addr4, ifmsh->addr, 6);

	plchdr->fn = 0;
	plchdr->sn = ++ifmsh->mgmt_sn;

	pos = skb_put_zero(nskb, 79);
	// category
	*pos++ = WLAN_CATEGORY_SELF_PROTECTED;

	// action
	*pos++ = action;

	// meshid + meshconf
	memcpy(pos, &local_prof, sizeof(local_prof));
	pos = pos + sizeof(local_prof);

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
	if (action == AK60211_SP_MESH_PEERING_CONFIRM)
		put_unaligned_le16(plid, pos);

	pos += 2;

	// reason
	if (action == AK60211_SP_MESH_PEERING_CLOSE)
		put_unaligned_le16(0x0, pos);

	pos += 2;

	skb_reset_mac_header(nskb);

	ak60211_pkt_hex_dump(nskb, "ak60211_send", 0);

	br_hmc_forward(nskb, plc);
}

int ak60211_mpath_sel_frame_tx(enum ak60211_mpath_frame_type action, u8 flags,
			       const u8 *orig_addr, u32 orig_sn,
			       const u8 *target, u32 target_sn, const u8 *da,
			       u8 hop_count, u8 ttl, u32 lifetime, u32 metric,
			       u32 preq_id, struct ak60211_if_data *ifmsh)
{
	struct sk_buff *skb;
	struct plc_packet_union *plcpkts;
	u8 *pos, ie_len;
	int hdr_len = sizeof(struct ethhdr) + sizeof(struct plc_hdr);
	u8 sa[ETH_ALEN];

	PLC_TRACE();
	switch (action) {
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

	if (!skb)
		return -1;

	skb_reserve(skb, 2);

	memcpy(sa, ifmsh->addr, ETH_ALEN);
	pos = skb_put_zero(skb, hdr_len);
	plc_fill_ethhdr(pos, da, ifmsh->addr, ntohs(0xAA55));

	plcpkts = (struct plc_packet_union *)pos;
	plcpkts->plchdr.framectl = cpu_to_le16(AK60211_FTYPE_MGMT |
							  AK60211_STYPE_ACTION);

	memcpy(plcpkts->plchdr.machdr.h_addr1, da, ETH_ALEN);
	memcpy(plcpkts->plchdr.machdr.h_addr2, sa, ETH_ALEN);
	memcpy(plcpkts->plchdr.machdr.h_addr3, target, ETH_ALEN);
	memcpy(plcpkts->plchdr.machdr.h_addr4, sa, ETH_ALEN);

	plcpkts->un.preq.category = WLAN_CATEGORY_MESH_ACTION;
	plcpkts->un.preq.action = WLAN_MESH_ACTION_HWMP_PATH_SELECTION;

	pos = (u8 *)&plcpkts->un.preq.elem.tag;
	switch (action) {
	case AK60211_MPATH_PREQ:
		plc_info("sending PREQ to %pM\n", target);
		*pos++ = WLAN_EID_PREQ;
		ie_len = 37;
		break;
	case AK60211_MPATH_PREP:
		plc_info("sending PREP to %pM\n", orig_addr);
		*pos++ = WLAN_EID_PREP;
		ie_len = 31;
		break;
	default:
		/* RANN and ERR */
		kfree_skb(skb);
		return -ENOTSUPP;
	}

	*pos++ = ie_len;
	*pos++ = flags;
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

static void ak60211_mesh_bcn_presp(struct plc_packet_union *buff,
				   struct ak60211_if_data *ifmsh)
{
	struct meshprofhdr peer;
	u16 stype;

	stype = (le16_to_cpu(buff->plchdr.framectl) & AK60211_FCTL_STYPE);

	if (stype == AK60211_STYPE_PROBE_RESP &&
	    memcmp(buff->plchdr.machdr.h_addr3, ifmsh->addr, ETH_ALEN))
		return;

	memcpy(&peer.meshid_elem, &buff->un.beacon.meshid_elem,
	       sizeof(struct meshidhdr));
	memcpy(&peer.meshconf_elem, &buff->un.beacon.meshconf_elem,
	       sizeof(struct meshconfhdr));

	if (!ak60211_mesh_match_local(&peer))
		return;

	ak60211_mesh_neighbour_update(ifmsh, buff);
}

static void ak60211_mesh_rx_mgmt_action(struct plc_packet_union *buff)
{
	switch (buff->un.self.category) {
	case WLAN_CATEGORY_SELF_PROTECTED:
		switch (buff->un.self.action) {
		case WLAN_SP_MESH_PEERING_OPEN:
		case WLAN_SP_MESH_PEERING_CLOSE:
		case WLAN_SP_MESH_PEERING_CONFIRM:
			ak60211_mesh_rx_plink_frame(&plcdev, buff);
			break;
		}
		break;
	case WLAN_CATEGORY_MESH_ACTION:
		if (buff->un.self.action ==
		    WLAN_MESH_ACTION_HWMP_PATH_SELECTION)
			ak60211_mesh_rx_path_sel_frame(&plcdev, buff);

		break;
	}
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

	if ((!!memcmp(plcbuff->da, plcdev.addr, ETH_ALEN)) &&
	    !is_broadcast_ether_addr(plcbuff->da))
		goto drop;

	if (htons(plcbuff->ethtype) == 0xAA66) {
		/* Temprary */
		nl60211_rx_callback(pskb);
		goto drop;
	}

	//plc_info("eth type = %x\n", htons(plcbuff->ethtype));
	if (htons(plcbuff->ethtype) != 0xAA55)
		goto drop;

	ftype = (le16_to_cpu(plcbuff->plchdr.framectl) & AK60211_FCTL_FTYPE);
	stype = (le16_to_cpu(plcbuff->plchdr.framectl) & AK60211_FCTL_STYPE);

	switch (ftype) {
	case AK60211_FTYPE_MGMT:
		switch (stype) {
		case AK60211_STYPE_BEACON:
			plc_info("S_BEACON\n");
			ak60211_mesh_bcn_presp(plcbuff, &plcdev);
			break;
		case AK60211_STYPE_PROBE_RESP:
			plc_info("S_PROBE_RESP\n");
			break;
		case AK60211_STYPE_ACTION:
			plc_info("S_ACTION\n");
			ak60211_mesh_rx_mgmt_action(plcbuff);
			break;
		}
		break;
	case AK60211_FTYPE_CTRL:

		break;
	case AK60211_FTYPE_DATA:
		switch (stype) {
		case AK60211_STYPE_QOSDATA:
			plc_info("S_QOSDATA\n");
			break;
		}
		break;
	}

	return NF_ACCEPT;
drop:
	return NF_DROP;
}

static int ak60211_sta_info_init(struct ak60211_if_data *ifmsh)
{
	int err;

	err = rhltable_init(&ifmsh->sta_hash, &ak60211_sta_rht_params);
	if (err)
		return err;

	mutex_init(&ifmsh->sta_mtx);
	INIT_LIST_HEAD(&ifmsh->sta_list);

	return 0;
}

static void plc_gen_sbeacon(struct plc_packet_union *buff)
{
	char meshid[MAX_MESH_ID_LEN] = {0};

	meshid[0] = 'A';
	meshid[1] = 'k';
	meshid[2] = 'i';
	meshid[3] = 'r';
	meshid[4] = 'a';
	meshid[5] = 'N';
	meshid[6] = 'e';
	meshid[7] = 't';

	buff->plchdr.framectl = 0x0080;
	buff->plchdr.duration_id = 0x0000;

	buff->plchdr.machdr.h_addr1[0] = 0xff;
	buff->plchdr.machdr.h_addr1[1] = 0xff;
	buff->plchdr.machdr.h_addr1[2] = 0xff;
	buff->plchdr.machdr.h_addr1[3] = 0xff;
	buff->plchdr.machdr.h_addr1[4] = 0xff;
	buff->plchdr.machdr.h_addr1[5] = 0xff;
	buff->plchdr.machdr.h_addr2[0] = 0x0;
	buff->plchdr.machdr.h_addr2[1] = 0x0;
	buff->plchdr.machdr.h_addr2[2] = 0x0;
	buff->plchdr.machdr.h_addr2[3] = 0x0;
	buff->plchdr.machdr.h_addr2[4] = 0x0;
	buff->plchdr.machdr.h_addr2[5] = 0x0;
	buff->plchdr.machdr.h_addr3[0] = 0xff;
	buff->plchdr.machdr.h_addr3[1] = 0xff;
	buff->plchdr.machdr.h_addr3[2] = 0xff;
	buff->plchdr.machdr.h_addr3[3] = 0xff;
	buff->plchdr.machdr.h_addr3[4] = 0xff;
	buff->plchdr.machdr.h_addr3[5] = 0xff;
	buff->plchdr.machdr.h_addr4[0] = 0x0;
	buff->plchdr.machdr.h_addr4[1] = 0x0;
	buff->plchdr.machdr.h_addr4[2] = 0x0;
	buff->plchdr.machdr.h_addr4[3] = 0x0;
	buff->plchdr.machdr.h_addr4[4] = 0x0;
	buff->plchdr.machdr.h_addr4[5] = 0x0;
	buff->plchdr.machdr.h_addr5[0] = 0x0;
	buff->plchdr.machdr.h_addr5[1] = 0x0;
	buff->plchdr.machdr.h_addr5[2] = 0x0;
	buff->plchdr.machdr.h_addr5[3] = 0x0;
	buff->plchdr.machdr.h_addr5[4] = 0x0;
	buff->plchdr.machdr.h_addr5[5] = 0x0;
	buff->plchdr.machdr.h_addr6[0] = 0x0;
	buff->plchdr.machdr.h_addr6[1] = 0x0;
	buff->plchdr.machdr.h_addr6[2] = 0x0;
	buff->plchdr.machdr.h_addr6[3] = 0x0;
	buff->plchdr.machdr.h_addr6[4] = 0x0;
	buff->plchdr.machdr.h_addr6[5] = 0x0;

	buff->plchdr.fn = 0;
	buff->plchdr.sn = 0;

	buff->un.beacon.meshid_elem.elemid = 114;
	buff->un.beacon.meshid_elem.len = MAX_MESH_ID_LEN;
	memset(buff->un.beacon.meshid_elem.meshid, 0, MAX_MESH_ID_LEN);
	memcpy(buff->un.beacon.meshid_elem.meshid, meshid, MAX_MESH_ID_LEN);

	buff->un.beacon.meshconf_elem.elemid = 113;
	buff->un.beacon.meshconf_elem.len = 7;
	buff->un.beacon.meshconf_elem.psel_protocol = 1;
	buff->un.beacon.meshconf_elem.psel_metric = 0;
	buff->un.beacon.meshconf_elem.congestion_ctrl_mode = 0;
	buff->un.beacon.meshconf_elem.sync_method = 0;
	buff->un.beacon.meshconf_elem.auth_protocol = 0;
	buff->un.beacon.meshconf_elem.mesh_formation.connected_to_gate = 0;
	buff->un.beacon.meshconf_elem.mesh_formation.num_of_peerings = 0;
	buff->un.beacon.meshconf_elem.mesh_formation.connected_as = 0;
	buff->un.beacon.meshconf_elem.mesh_cap.accepting_addi_mesh_peerings = 1;
	buff->un.beacon.meshconf_elem.mesh_cap.mcca_sup = 0;
	buff->un.beacon.meshconf_elem.mesh_cap.mcca_en = 0;
	buff->un.beacon.meshconf_elem.mesh_cap.forwarding = 1;
	buff->un.beacon.meshconf_elem.mesh_cap.mbca_en = 0;
	buff->un.beacon.meshconf_elem.mesh_cap.tbtt_adjusting = 0;
	buff->un.beacon.meshconf_elem.mesh_cap.ps = 0;
	buff->un.beacon.meshconf_elem.mesh_cap.reserved = 0;
}

void plc_send_beacon(void)
{
	struct sk_buff *nskb;
	struct plc_packet_union sbeacon;
	int beacon_len = sizeof(struct ethhdr) +
			 sizeof(struct plc_hdr) +
			 sizeof(struct beacon_pkts);
	u8 *pos;

	PLC_TRACE();

	// beacon packet size is 92 bytes
	nskb = dev_alloc_skb(2 + beacon_len + 2);
	if (!nskb)
		return;

	plc_gen_sbeacon(&sbeacon);

	skb_reserve(nskb, 2);

	pos = skb_put_zero(nskb, beacon_len);

	plc_fill_ethhdr((u8 *)&sbeacon, broadcast_addr,
			plc->br_addr, ntohs(0xAA55));

	memcpy(sbeacon.plchdr.machdr.h_addr2, plc->br_addr, ETH_ALEN);
	memcpy(sbeacon.plchdr.machdr.h_addr4, plc->br_addr, ETH_ALEN);

	memcpy(pos, &sbeacon, beacon_len);

	skb_reset_mac_header(nskb);
	/* not sure network header:
	 * add cause "protocol xxxx is buggy, dev eth0"
	 */
	skb_set_network_header(nskb, sizeof(struct ethhdr));

	ak60211_pkt_hex_dump(nskb, "plc_beacon_send", 0);

	br_hmc_forward(nskb, plc);
}

void ak60211_preq_test_wq(struct work_struct *work)
{
	struct ak60211_mesh_path *mpath;
	u8 ttl = 0;
	u32 lifetime = 0;

	PLC_TRACE();

	mpath = ak60211_mpath_lookup(&plcdev, plc->path->dst);
	if (!mpath) {
		mpath = ak60211_mpath_add(&plcdev, plc->path->dst);
		if (!mpath) {
			plc_err("mpath build up fail\n");
			return;
		}
	}

	plcdev.sn = plc->path->sn;
	mpath->flags |= PLC_MESH_PATH_RESOLVING;
	ttl = MAX_MESH_TTL;
	lifetime = MSEC_TO_TU(AK60211_MESH_HWMP_PATH_TIMEOUT);
	ak60211_mpath_sel_frame_tx(AK60211_MPATH_PREQ, mpath->flags,
				   plcdev.addr, plcdev.sn, mpath->dst,
				   mpath->sn, broadcast_addr, 0, ttl,
				   lifetime, 0, ++plcdev.preq_id, &plcdev);

	//plc->path->flags = mpath->flags;
	plc->path->flags = BR_HMC_PATH_ACTIVE;

	br_hmc_path_update(plc);
}

void ak60211_mpath_queue_preq_new(struct hmc_hybrid_path *hmpath)
{
	__ak60211_mpath_queue_preq_new(&plcdev, hmpath, AK60211_PREQ_START);
}

void ak60211_mpath_queue_preq(const u8 *dst, u32 hmc_sn)
{
	__ak60211_mpath_queue_preq(&plcdev, dst, hmc_sn);
}

static void ak60211_mesh_housekeeping(struct ak60211_if_data *ifmsh)
{
	//PLC_TRACE();
	if (ifmsh->mshcfg.plink_timeout > 0)
		ak60211_sta_expire(ifmsh, ifmsh->mshcfg.plink_timeout * HZ);

	ak60211_mtbl_expire(ifmsh);

	mod_timer(&ifmsh->housekeeping_timer, round_jiffies(jiffies +
				AK60211_MESH_HOUSEKEEPING_INTERVAL));
}

void ak60211_iface_work(struct work_struct *work)
{
	struct ak60211_if_data *ifmsh = &plcdev;

	ak60211_dev_lock(ifmsh);
	if (!ifmsh->mesh_id_len)
		goto out;

	if (ifmsh->preq_queue_len && time_after(jiffies,
	    ifmsh->last_preq + msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPpreqMinInterval)))
		ak60211_mpath_start_discovery(ifmsh);

	if (test_and_clear_bit(MESH_WORK_HOUSEKEEPING, &ifmsh->wrkq_flags))
		ak60211_mesh_housekeeping(ifmsh);
out:
	ak60211_dev_unlock(ifmsh);
}

static void ak60211_mesh_path_timer(struct timer_list *t)
{
	struct ak60211_if_data *ifmsh = from_timer(ifmsh, t, mesh_path_timer);

	queue_work(ifmsh->workqueue, &ifmsh->work);
}

static void ak60211_mesh_housekeeping_timer(struct timer_list *t)
{
	struct ak60211_if_data *ifmsh =
	    from_timer(ifmsh, t, housekeeping_timer);

	set_bit(MESH_WORK_HOUSEKEEPING, &plcdev.wrkq_flags);
	queue_work(ifmsh->workqueue, &ifmsh->work);
}

static void ak60211_mesh_wrkq_start(struct ak60211_if_data *ifmsh)
{
	PLC_TRACE();
	ifmsh->workqueue = alloc_ordered_workqueue("mesh_wrkq", 0);
	WARN_ON(!ifmsh->workqueue);

	INIT_WORK(&ifmsh->work, ak60211_iface_work);
	queue_work(ifmsh->workqueue, &ifmsh->work);
}

bool ak60211_mesh_init(u8 *id, u8 *mac)
{
	size_t id_len;

	PLC_TRACE();
	memset(&plcdev, 0, sizeof(struct ak60211_if_data));
	memcpy(&plcdev.mshcfg, &default_mesh_config,
	       sizeof(struct ak60211_mesh_config));

	memcpy(&plcdev.addr, mac, ETH_ALEN);

	id_len = strlen(id);
	if (id_len >= MAX_MESH_ID_LEN) {
		plc_err("mesh id len is too long\n");
		return false;
	}
	plc_info("plc interface addr is %pM\n", plcdev.addr);
	plcdev.mesh_id_len = id_len;
	memcpy(plcdev.mesh_id, id, id_len);
	plc_info("plc mesh id: %s\n", plcdev.mesh_id);

	timer_setup(&plcdev.housekeeping_timer,
		    ak60211_mesh_housekeeping_timer, 0);
	set_bit(MESH_WORK_HOUSEKEEPING, &plcdev.wrkq_flags);
	atomic_set(&plcdev.mpaths, 0);
	plcdev.last_preq = jiffies;

	mutex_init(&plcdev.mtx);

	ak60211_mpath_tbl_init(&plcdev);
	ak60211_sta_info_init(&plcdev);

	timer_setup(&plcdev.mesh_path_timer, ak60211_mesh_path_timer, 0);
	INIT_LIST_HEAD(&plcdev.preq_queue.list);
	spin_lock_init(&plcdev.mesh_preq_queue_lock);

	ak60211_mesh_wrkq_start(&plcdev);

	return true;
}

void ak60211_mesh_deinit(void)
{
	PLC_TRACE();

	del_timer_sync(&plcdev.housekeeping_timer);
	del_timer_sync(&plcdev.mesh_path_timer);
	list_del_rcu(&plcdev.sta_list);

	if (plcdev.workqueue) {
		cancel_work_sync(&plcdev.work);
		flush_workqueue(plcdev.workqueue);
		destroy_workqueue(plcdev.workqueue);
	}

	ak60211_mtbl_deinit(&plcdev);
}
