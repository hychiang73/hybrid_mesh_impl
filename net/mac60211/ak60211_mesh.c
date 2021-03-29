#include <ak60211_mesh_private.h>
#include <mac60211.h>
#include <nl60211.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <net/arp.h>
#include <net/neighbour.h>


#define MESH_TTL		31
#define MESH_DEFAULT_ELEMENT_TTL 31
#define MESH_MAX_RETR	3
#define MESH_RET_T		100
#define MESH_CONF_T		100
#define MESH_HOLD_T		100

#define MESH_PATH_TIMEOUT	1000
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
	/* .max_size = CONFIG_MAC80211_STA_HASH_MAX_SIZE, */
};

struct ak60211_if_data *ak60211_dev_to_ifdata(void)
{
	return &plcdev;
}
EXPORT_SYMBOL(ak60211_dev_to_ifdata);

void ak60211_pkt_hex_dump(struct sk_buff *pskb, const char *type, int offset)
{
	size_t len;
	int rowsize = 16;
	int i, l, linelen, remaining;
	int li = 0;
	struct sk_buff *skb;
	/*
	const struct arphdr *arp;
	unsigned char *arp_ptr;
	unsigned char *sha;
	unsigned char *tha = NULL;
	__be32 sip, tip;
	u16 dev_type;
	*/
	u8 *data, ch;

	if (!plc_dbg)
		return;

	skb = skb_copy(pskb, GFP_ATOMIC);
	data = (u8 *)skb_mac_header(skb);

	/* arp = arp_hdr(skb); */
	if (skb_is_nonlinear(skb))
		len = skb->data_len;
	else
		len = skb->len;

#if 0  // for debug, just save it but not use in gerenal
	if (skb->dev) {
		struct net_device *indev, *brdev;
		struct in_device *in_dev = __in_dev_get_rcu(skb->dev);
		struct neighbour *n;
		struct net_bridge_port *p = ak_port_get_rcu(skb->dev);

		brdev = p->br->dev;

		if (!brdev) {
			plc_err("brdev is NULL\n");
			goto BR_DEV_NULL;
		}

		indev = skb->dev;
		skb->dev = brdev;
		dev_type = skb->dev->type;
		plc_info("dev_type = %x\n", dev_type);
		if (arp->ar_hln != skb->dev->addr_len)
			plc_err("ar_hln != dev->addr_len\n");

		arp_ptr = (unsigned char *)(arp + 1);
		/* sha = sender hardware address
		 * sip = sender ip address
		 * tha = target hardware address
		 * tip = target ip address
		 * */
		sha	= arp_ptr;
		arp_ptr += skb->dev->addr_len;
		memcpy(&sip, arp_ptr, 4);
		arp_ptr += 4;

		tha = arp_ptr;
		arp_ptr += skb->dev->addr_len;
		memcpy(&tip, arp_ptr, 4);

		plc_info("sha:%pM, tha:%pM\n", sha, tha);
		plc_info("sip:%d, tip:%d\n", sip, tip);

		if (ipv4_is_multicast(tip))
			plc_err("tip is multicast\n");
		if (ipv4_is_loopback(tip))
			plc_err("tip is loopback\n");
		if (sip == tip)
			plc_err("sip = tip\n");
		if (sip == 0)
			plc_err("sip = 0\n");
		if (arp->ar_pln != 4)
			plc_err("ar_pln != 4\n");
		if (arp->ar_hrd != htons(ARPHRD_ETHER))
			plc_err("ar_hrd != ARPHRD_ETHER\n");
		if (arp->ar_hrd != htons(ARPHRD_IEEE802))
			plc_err("ar_hrd != ARPHRD_EEE802\n");
		if (arp->ar_pro != htons(ETH_P_IP))
			plc_err("ar_pro != ETH_P_IP\n");
		if (arp->ar_op != htons(ARPOP_REPLY) &&
				arp->ar_op != htons(ARPOP_REQUEST))
			plc_err("arp_op != AROPO_REP/REQ\n");

		if (arp->ar_op == htons(ARPOP_REQUEST)) {
			plc_info("arp_op is ARPOP_REQUEST\n");
		}
		if (arp->ar_op == htons(ARPOP_REPLY)) {
			plc_info("arp op is ARPOP_REPLY\n");
		}

		n = __neigh_lookup(&arp_tbl, &sip, skb->dev, 0);

		if (!n)
			plc_err("neigh is not exist\n");
		if (!IN_DEV_ARP_ACCEPT(in_dev))
			plc_err("ARP_ACCEPT in dev is false\n");
	} else {
BR_DEV_NULL:
		plc_err("skb->dev is NULL\n");
	}
#endif
	if (skb->data != data) {
		plc_info("skb->data != skb->mac_header\n");
		len += 14;
	}
	remaining = len + 2 + offset;

	pr_info("Packet hex dump (len = %ld, %d):\n", len, skb->data_len);
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
	kfree_skb(skb);
}

static int __must_check
		__ak60211_sta_info_destroy(struct ak60211_sta_info *sta,
					   struct ak60211_if_data *ifmsh)
{
	int ret;

	/* destroy part1 */
	might_sleep();

	if (!sta)
		return -ENONET;

	lockdep_assert_held(&ifmsh->sta_mtx);

	ret = rhltable_remove(&ifmsh->sta_hash, &sta->hash_node,
			      ak60211_sta_rht_params);
	if (WARN_ON(ret))
		return ret;

	list_del_rcu(&sta->list);

	/* destroy part2 */
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

	if (!ifmsh->hmc_ops)
		return;

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
	/* category */
	*pos++ = WLAN_CATEGORY_SELF_PROTECTED;

	/* action */
	*pos++ = action;

	/* meshid + meshconf */
	memcpy(pos, &local_prof, sizeof(local_prof));
	pos = pos + sizeof(local_prof);

	/* mpm_elem
	 * mesh peer protocol
	 */
	*pos++ = 117;
	*pos++ = 4;
	put_unaligned_le16(0x0000, pos);
	pos += 2;

	/* llid */
	put_unaligned_le16(llid, pos);
	pos += 2;

	/* plid */
	if (action == AK60211_SP_MESH_PEERING_CONFIRM)
		put_unaligned_le16(plid, pos);

	pos += 2;

	/* reason */
	if (action == AK60211_SP_MESH_PEERING_CLOSE)
		put_unaligned_le16(0x0, pos);

	pos += 2;

	skb_reset_mac_header(nskb);

	ak60211_pkt_hex_dump(nskb, "ak60211_send", 0);

	ifmsh->hmc_ops->xmit(nskb, HMC_PORT_PLC);
}

int ak60211_mpath_error_tx(struct ak60211_if_data *ifmsh, u8 ttl,
			   const u8 *target, u32 target_sn,
			   u16 target_rcode, const u8 *ra)
{
	struct sk_buff *skb;
	struct plc_packet_union *plcpkts;
	u8 *pos;
	int hdr_len = sizeof(struct ethhdr) + sizeof(struct plc_hdr) +
		      sizeof(struct perr_pkts);
	u8 sa[ETH_ALEN];

	PLC_TRACE();

	if (!ifmsh->hmc_ops)
		return -1;

	skb = dev_alloc_skb(2 + hdr_len + 2);

	if (!skb)
		return -1;

	skb_reserve(skb, 2);

	memcpy(sa, ifmsh->addr, ETH_ALEN);
	pos = skb_put_zero(skb, hdr_len);
	plc_fill_ethhdr(pos, ra, sa, ntohs(0xAA55));

	plcpkts = (struct plc_packet_union *)pos;
	plcpkts->plchdr.framectl = cpu_to_le16(AK60211_FTYPE_MGMT |
					       AK60211_STYPE_ACTION);

	memcpy(plcpkts->plchdr.machdr.h_addr1, ra, ETH_ALEN);
	memcpy(plcpkts->plchdr.machdr.h_addr2, sa, ETH_ALEN);
	memcpy(plcpkts->plchdr.machdr.h_addr3, ra, ETH_ALEN);
	memcpy(plcpkts->plchdr.machdr.h_addr4, sa, ETH_ALEN);

	plcpkts->un.perr.category = WLAN_CATEGORY_MESH_ACTION;
	plcpkts->un.perr.action = WLAN_MESH_ACTION_HWMP_PATH_SELECTION;
	pos = (u8 *)&plcpkts->un.perr.elem.tag;
	*pos++ = WLAN_EID_PERR;
	*pos++ = 15;
	*pos++ = ttl;
	*pos++ = 0;

	memcpy(pos, target, ETH_ALEN);
	pos += ETH_ALEN;
	put_unaligned_le32(target_sn, pos);
	pos += 4;
	put_unaligned_le16(target_rcode, pos);

	/* TODO: next_perr timer */
	skb_reset_mac_header(skb);

	ak60211_pkt_hex_dump(skb, "ak60211_mpath_error_tx", 0);

	ifmsh->hmc_ops->xmit(skb, HMC_PORT_PLC);

	return true;
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

	if (!ifmsh->hmc_ops)
		return -1;

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
	memcpy(plcpkts->plchdr.machdr.h_addr3, da, ETH_ALEN);
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
	ifmsh->hmc_ops->xmit(skb, HMC_PORT_PLC);

	return true;
}

void ak60211_plcto8023_unencap(struct ak60211_if_data *ifmsh,
							   struct plc_packet_union *buff,
							   struct sk_buff *skb)
{
	struct ethhdr eth;
	u8 *pos;
	u32 plchdrsize;

	rmb();
	pos = skb_mac_header(skb);

	plchdrsize = sizeof(struct plc_hdr) + sizeof(struct ak60211s_hdr);

	/* ak60211_pkt_hex_dump(skb, "ak60211_frame unencap(1)", 0); */

	memcpy(pos + ETH_ALEN * 2, skb->data + plchdrsize - 2, 2);
	memcpy(&eth, pos, sizeof(struct ethhdr));
	skb_pull(skb, plchdrsize);
	memcpy(skb_push(skb, sizeof(struct ethhdr)),
		   &eth, sizeof(struct ethhdr));

	skb->protocol = eth_type_trans(skb, skb->dev);

	skb_reset_network_header(skb);

	ak60211_pkt_hex_dump(skb, "ak60211_frame unencap(2)", 0);
}


void ak60211_mesh_data_handle(struct ak60211_if_data *ifmsh,
							  struct plc_packet_union *buff,
							  struct sk_buff *skb)
{
	PLC_TRACE();

	if (ether_addr_equal(buff->plchdr.machdr.h_addr3, ifmsh->addr)) {
		/* data is for us */
		plc_info("pkts is for us, send to ip layer\n");
		ak60211_plcto8023_unencap(ifmsh, buff, skb);
	}
}

void ak60211_fill_mesh_address(struct plc_hdr *hdr, __le16 *fc,
				const u8 *meshda, const u8 *meshsa)
{
	if (is_multicast_ether_addr(meshda)) {
		*fc |= cpu_to_le16(AK60211_FCTL_FROMDS);
		/* DA TA SA */
		memcpy(hdr->machdr.h_addr1, meshda, ETH_ALEN);
		memcpy(hdr->machdr.h_addr2, meshsa, ETH_ALEN);
		memcpy(hdr->machdr.h_addr3, meshda, ETH_ALEN);
		memcpy(hdr->machdr.h_addr4, meshsa, ETH_ALEN);
	} else {
		*fc |= cpu_to_le16(AK60211_FCTL_FROMDS | AK60211_FCTL_TODS);
		/* RA TA DA SA */
		eth_zero_addr(hdr->machdr.h_addr1);
		memcpy(hdr->machdr.h_addr2, meshsa, ETH_ALEN);
		memcpy(hdr->machdr.h_addr3, meshda, ETH_ALEN);
		memcpy(hdr->machdr.h_addr4, meshsa, ETH_ALEN);
	}
}

void ak60211_new_mesh_header(struct ak60211_if_data *ifmsh,
							 struct plc_packet_union *pkts,
							 const char *addr4or5, const char *addr6)
{
	if (WARN_ON(!addr4or5 && addr6))
		return;

	memset(&pkts->un.meshhdr, 0, sizeof(struct ak60211s_hdr));

	put_unaligned(cpu_to_le32(ifmsh->mesh_seqnum), &pkts->un.meshhdr.seqnum);
	ifmsh->mesh_seqnum++;

	if (addr4or5 && !addr6) {
		pkts->un.meshhdr.flags |= PLC_MESH_FLAGS_AE_A4;
		memcpy(pkts->plchdr.machdr.h_addr4, addr4or5, ETH_ALEN);
	} else if (addr4or5 && addr6) {
		pkts->un.meshhdr.flags |= PLC_MESH_FLAGS_AE_A5_A6;
		memcpy(pkts->plchdr.machdr.h_addr5, addr4or5, ETH_ALEN);
		memcpy(pkts->plchdr.machdr.h_addr6, addr6, ETH_ALEN);
	}
}

int ak60211_mesh_nexthop_lookup(struct ak60211_if_data *ifmsh,
								struct sk_buff *skb)
{
	struct ak60211_mesh_path *mpath;
	struct ak60211_sta_info *nexthop;
	struct plc_packet_union *plcpkts =
		(struct plc_packet_union *) skb->data;
	u8 *target_addr = plcpkts->plchdr.machdr.h_addr3;

	PLC_TRACE();
	mpath = ak60211_mpath_lookup(ifmsh, target_addr);
	if (!mpath || !(mpath->flags & PLC_MESH_PATH_ACTIVE))
		return -ENOENT;

	if (time_after(jiffies, mpath->exp_time -
	    msecs_to_jiffies(ifmsh->mshcfg.path_refresh_time)) &&
		ether_addr_equal(ifmsh->addr, plcpkts->plchdr.machdr.h_addr4) &&
		!(mpath->flags & PLC_MESH_PATH_RESOLVING) &&
		!(mpath->flags & PLC_MESH_PATH_FIXED))
		ak60211_mpath_queue_preq(target_addr);

	nexthop = rcu_dereference(mpath->next_hop);
	if (nexthop) {
		memcpy(plcpkts->plchdr.machdr.h_addr1, nexthop->addr, ETH_ALEN);
		memcpy(plcpkts->plchdr.machdr.h_addr2, ifmsh->addr, ETH_ALEN);
		return 0;
	}

	return -ENOENT;
}

int ak60211_nexthop_resolved(struct sk_buff *skb, u8 iface_id)
{
	/* This function is for the packets which is generated by myself
	 * return value -
	 * NF_DROP: nexthop resolved failed, no process the skb
	 * NF_ACCEPT: nexthop resolved success, start to xmit
	 * -ENOMEN: skb error, free the skb
	 */
	struct ak60211_if_data *ifmsh = ak60211_dev_to_ifdata();
	struct ak60211_mesh_path *mpath = NULL, *mppath = NULL;
	struct plc_packet_union plcpkts;
	int skip_header_bytes, head_need;
	int ret;
	u16 ethertype, hdrlen = sizeof(struct ethhdr) + sizeof(struct plc_hdr) + sizeof(struct ak60211s_hdr);
	__le16 fc = 0;
	bool multicast;

	if (!ifmsh->hmc_ops)
		goto resolved_failed;

	/* ak60211_pkt_hex_dump(skb, "ak60211_nexthop_resolved(ORI)", 0); */
	ethertype = (skb->data[12] << 8) | skb->data[13];
	memcpy(&plcpkts, skb->data, sizeof(struct ethhdr));
	fc = cpu_to_le16(AK60211_FTYPE_DATA |
					AK60211_STYPE_QOSDATA);

	mpath = ak60211_mpath_lookup(ifmsh, skb->data);
	if (!mpath || !(mpath->flags & PLC_MESH_PATH_ACTIVE))
		goto resolved_failed;

	if (!ether_addr_equal(ifmsh->addr, skb->data + ETH_ALEN)) {
		plc_info("sa is not plc, exit\n");
		/* ifmsh->hmc_ops->xmit(skb, iface_id); */
		goto resolved_failed;
	}

	if (!is_multicast_ether_addr(skb->data)) {
		struct ak60211_sta_info *nexthop;
		bool mpp_lookup = true;

		/* mpath = ak60211_mpath_lookup(ifmsh, skb->data); */
		if (mpath) {
			mpp_lookup = false;
			nexthop = rcu_dereference(mpath->next_hop);

			/* TODO: mpp table */
			if (!nexthop ||
				!(mpath->flags &
				  (PLC_MESH_PATH_ACTIVE |
				   PLC_MESH_PATH_RESOLVING)))
				mpp_lookup = true;

			if (mpp_lookup)
				;/* TODO: mpp table check*/
		}
	}

	if (ether_addr_equal(ifmsh->addr, skb->data + ETH_ALEN) /*&&
			!(mppath && !ether_addr_equal(mppath->mpp, skb->data)))*/ || 1) {
		/* ?????????  need to check */
		ak60211_fill_mesh_address(&plcpkts.plchdr, &fc,
								  skb->data,
								  skb->data + ETH_ALEN);
		ak60211_new_mesh_header(ifmsh, &plcpkts, NULL, NULL);
	} else {
		const u8 *mesh_da = skb->data;

		if (mppath)
			;/*mesh_da = mppath->mpp;*/
		else if (mpath)
			mesh_da = mpath->dst;

		ak60211_fill_mesh_address(&plcpkts.plchdr, &fc, mesh_da,
								ifmsh->addr);
		if (is_multicast_ether_addr(mesh_da)) {
			/* multacast: DA, TA, mSA AE:SA */
		} else {
			/* RA TA mDa mSA AE:DA SA */
			ak60211_new_mesh_header(ifmsh, &plcpkts,
					skb->data, skb->data + ETH_ALEN);
		}
	}

	multicast = is_multicast_ether_addr(plcpkts.plchdr.machdr.h_addr1);

	if (skb_shared(skb)) {
		struct sk_buff *tmp_skb = skb;

		skb = skb_clone(skb, GFP_ATOMIC);
		kfree_skb(tmp_skb);
		if (!skb) {
			ret = -ENOMEM;
			goto free;
		}
	}

	plcpkts.ethtype = ntohs(0xAA55);
	plcpkts.plchdr.framectl = fc;
	plcpkts.plchdr.duration_id = 0;
	plcpkts.un.meshhdr.ethtype = ntohs(ethertype);

	skip_header_bytes = ETH_HLEN;

	/*
	if (ethertype == ETH_P_AARP || ethertype == ETH_P_IPX) {
		TODO: bridge tunnel header?
	} else if (ethertype >= ETH_P_802_3_MIN) {
		rfc1042_header?
	} else {

	}
	*/

	skb_pull(skb, skip_header_bytes);
	head_need = hdrlen - skb_headroom(skb);

	if (head_need > 0 || skb_cloned(skb)) {
		plc_info("cloned\n");
		head_need += 2; /* sdata->encrypt_headroom */
		head_need += 2; /* local->tx_headroom */
		head_need = max_t(int, 0, head_need);
		if (pskb_expand_head(skb, head_need, 0, GFP_ATOMIC)) {
			plc_err("pskb_expand failed\n");
			dev_kfree_skb_any(skb);
			skb = NULL;
			return -ENOMEM;
		}
	}

	memcpy(skb_push(skb, hdrlen), &plcpkts, hdrlen);
	skb_reset_mac_header(skb);

	ak60211_pkt_hex_dump(skb, "ak60211_nexthop_resolved(PLC)", 0);
	if (!ak60211_mesh_nexthop_lookup(ifmsh, skb)) {
		ifmsh->hmc_ops->xmit(skb, iface_id);
	} else {
		plc_err("plc xmit failed\n");
		// ifmsh->hmc_ops->path_del(plcpkts.plchdr.machdr.h_addr3);
		goto resolved_failed;
	}

	return NF_ACCEPT;

free:
	kfree_skb(skb);
	return -ENOMEM;

resolved_failed:
	return NF_DROP;
}
EXPORT_SYMBOL(ak60211_nexthop_resolved);

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

int ak60211_rx_handler(struct sk_buff *pskb, struct sk_buff *nskb)
{
	struct plc_packet_union *plcbuff;
	u16 stype, ftype;

	plcbuff = (struct plc_packet_union *)skb_mac_header(pskb);
	if (!is_valid_ether_addr(plcbuff->sa)) {
		/* not muitlcast or zero ether addr */
		goto drop;
	}

	if (ether_addr_equal(plcbuff->sa, plcdev.addr)) {
		plc_err("send by myself, drop the packet\n");
		goto drop;
	}

	if (!(ether_addr_equal(plcbuff->da, plcdev.addr)) &&
	    !is_broadcast_ether_addr(plcbuff->da))
		goto drop;

	if (htons(plcbuff->ethtype) == 0xAA66) {
		/* Temprary */
		nl60211_rx_callback(pskb);
		goto drop;
	}

	if (htons(plcbuff->ethtype) != 0xAA55) {
		goto drop;
	}

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
			ak60211_mesh_data_handle(&plcdev, plcbuff, pskb);
			goto drop;
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
	struct ak60211_if_data *ifmsh = ak60211_dev_to_ifdata();
	int beacon_len = sizeof(struct ethhdr) +
			 sizeof(struct plc_hdr) +
			 sizeof(struct beacon_pkts);
	u8 *pos;

	PLC_TRACE();

	if (!ifmsh->hmc_ops)
		return;

	// beacon packet size is 92 bytes
	nskb = dev_alloc_skb(2 + beacon_len + 2);
	if (!nskb)
		return;

	plc_gen_sbeacon(&sbeacon);

	skb_reserve(nskb, 2);

	pos = skb_put_zero(nskb, beacon_len);

	plc_fill_ethhdr((u8 *)&sbeacon, broadcast_addr,
			plcdev.addr, ntohs(0xAA55));

	memcpy(sbeacon.plchdr.machdr.h_addr2, plcdev.addr, ETH_ALEN);
	memcpy(sbeacon.plchdr.machdr.h_addr4, plcdev.addr, ETH_ALEN);

	memcpy(pos, &sbeacon, beacon_len);

	skb_reset_mac_header(nskb);
	/* not sure network header:
	 * add cause "protocol xxxx is buggy, dev eth0"
	 */
	skb_set_network_header(nskb, sizeof(struct ethhdr));

	ak60211_pkt_hex_dump(nskb, "plc_beacon_send", 0);

	ifmsh->hmc_ops->xmit(nskb, HMC_PORT_PLC);
}

int ak60211_mpath_queue_preq(const u8 *addr)
{
	return __ak60211_mpath_queue_preq(&plcdev, addr, AK60211_PREQ_START);
}

static void ak60211_mesh_housekeeping(struct ak60211_if_data *ifmsh)
{
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

	if (ifmsh->preq_queue_len &&
	    time_after(jiffies, ifmsh->last_preq + msecs_to_jiffies(ifmsh->mshcfg.MeshHWMPpreqMinInterval)))
		ak60211_mpath_start_discovery(ifmsh);

	if (test_and_clear_bit(AK60211_MESH_WORK_HOUSEKEEPING, &ifmsh->wrkq_flags))
		ak60211_mesh_housekeeping(ifmsh);
out:
	ak60211_dev_unlock(ifmsh);
}

void ak60211_mplink_timer(struct timer_list *t)
{
	struct ak60211_sta_info *sta = from_timer(sta, t, plink_timer);
	u16 reason = 0;
	enum ak60211_sp_actioncode action = 0;
	struct ak60211_if_data *local = sta->local;

	PLC_TRACE();
	spin_lock_bh(&sta->plink_lock);

	if (time_before(jiffies, sta->plink_timer.expires)) {
		plc_info("Ignoring timer for %pM in state %s (timer adjusted)\n",
			 sta->addr, mplstates[sta->plink_state]);
		spin_unlock_bh(&sta->plink_lock);
		return;
	}

	if (sta->plink_state == AK60211_PLINK_LISTEN ||
	    sta->plink_state == AK60211_PLINK_ESTAB) {
		plc_info("Ignoring timer for %pM in state %s (timer deleted)\n",
			 sta->addr, mplstates[sta->plink_state]);
		spin_unlock_bh(&sta->plink_lock);
		return;
	}

	plc_info("Mesh plink timer for %pM fired on state %s\n",
		 sta->addr, mplstates[sta->plink_state]);
	switch (sta->plink_state) {
	case AK60211_PLINK_OPN_RCVD:
	case AK60211_PLINK_OPN_SNT:
		if (sta->plink_retries < local->mshcfg.MeshMaxRetries) {
			u32 rand;

			plc_info("Send OPEN to %pM (retry, timeout): %d %d\n",
				 sta->addr, sta->plink_retries,
				 sta->plink_timeout);
			get_random_bytes(&rand, sizeof(u32));
			sta->plink_timeout = sta->plink_timeout +
					     rand % sta->plink_timeout;
			++sta->plink_retries;
			mod_timer(&sta->plink_timer, jiffies +
				  msecs_to_jiffies(sta->plink_timeout));
			action = WLAN_SP_MESH_PEERING_OPEN;
			break;
		}
		reason = WLAN_REASON_MESH_MAX_RETRIES;
		/* fall through */
	case AK60211_PLINK_CNF_RCVD:
		/* confirm timer */
		if (!reason)
			reason = WLAN_REASON_MESH_CONFIRM_TIMEOUT;
		sta->plink_state = AK60211_PLINK_HOLDING;
		mod_timer(&sta->plink_timer, jiffies +
			  msecs_to_jiffies(local->mshcfg.MeshHoldingTimeout));
		plc_info("Send CLOSE to %pM\n", sta->addr);
		action = WLAN_SP_MESH_PEERING_CLOSE;
		break;
	case AK60211_PLINK_HOLDING:
		/* holding timer */
		del_timer(&sta->plink_timer);
		ak60211_mesh_plink_fsm_restart(sta);
		break;
	default:
		break;
	}
	spin_unlock_bh(&sta->plink_lock);
	if (action)
		ak60211_mesh_plink_frame_tx(local, action, sta->addr,
					    sta->llid, sta->plid);
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

	set_bit(AK60211_MESH_WORK_HOUSEKEEPING, &plcdev.wrkq_flags);
	queue_work(ifmsh->workqueue, &ifmsh->work);
}

static inline void ak60211_mplink_timer_set(struct ak60211_sta_info *sta,
					    u32 timeout)
{
	sta->plink_timeout = timeout;
	mod_timer(&sta->plink_timer, jiffies +
				msecs_to_jiffies(timeout));
}

static void ak60211_mesh_wrkq_start(struct ak60211_if_data *ifmsh)
{
	PLC_TRACE();
	ifmsh->workqueue = alloc_ordered_workqueue("mesh_wrkq", 0);
	WARN_ON(!ifmsh->workqueue);

	INIT_WORK(&ifmsh->work, ak60211_iface_work);
	queue_work(ifmsh->workqueue, &ifmsh->work);
}

int ak60211_mesh_hmc_ops_register(const struct ak60211_hmc_ops *ops)
{
	if (!ops->path_update || !ops->xmit)
		return -EINVAL;

	plcdev.hmc_ops = ops;
	return 0;
}
EXPORT_SYMBOL(ak60211_mesh_hmc_ops_register);

void ak60211_mesh_hmc_ops_unregister(void)
{
	plcdev.hmc_ops = NULL;
}
EXPORT_SYMBOL(ak60211_mesh_hmc_ops_unregister);

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
	set_bit(AK60211_MESH_WORK_HOUSEKEEPING, &plcdev.wrkq_flags);
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
