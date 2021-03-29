#define IN_JETSON (1)

#if IN_JETSON
#include "../hmc/hmc.h"
#include "mac60211.h"
#include "ak60211_mesh_private.h"
#include "nl60211.h"
#include "nl60211_uapi.h"
#endif
#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>

#define PID_OF_SENDER  nlreq->nl_msghdr.nlmsg_pid
#define IF_INDEX       nlreq->if_index
#define COMMAND_TYPE   nlreq->nl_msghdr.nlmsg_type

static struct sock *nl_sk;
static int pid_of_receiver;
static unsigned int if_index_recv;
static unsigned int command_type_recv;
static unsigned int is_nl60211_in_recv;
static unsigned int is_nl60211_in_recv_once;
static unsigned char recv_ether_type[2];

struct nl60211_ctrl_para g_nl60211_ctrl_para = {NL60211_VERSION};

void nl60211_nlmsghdr_copy(struct nl60211msg *to, struct nl60211msg *from)
{
	to->nl_msghdr.nlmsg_type = from->nl_msghdr.nlmsg_type;
	to->nl_msghdr.nlmsg_pid = from->nl_msghdr.nlmsg_pid;
	to->if_index = from->if_index;
}

void nl60211_util_gen_pkt(
	unsigned int total_len,
	unsigned char *raw,
	u32 type)
{
#if IN_JETSON
	unsigned int i = 0;
	unsigned int proto = 0xAA66;
	struct sk_buff *new_sk;
	struct ethhdr *ether;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	//const u8 da[ETH_ALEN] = {0x00,0x04,0x4b,0xe6,0xec,0x3d};
	//const u8 da[ETH_ALEN] = {0x00,0x19,0x94,0x38,0xfd,0x8e};
	//const u8 sa[ETH_ALEN] = {0x00,0x04,0x4b,0xec,0x28,0x3b};
	u8 da[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u8 sa[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	u8 *pos;
	int egress = -1;

	type = type & NL60211_CMD_MASK;

	if (!pdata->hmc_ops) {
		pr_err("nl60211_util_gen_pkt() error, can't find hmc_ops!\n");
		return;
	}

	for (i = 0; i < total_len; i++) {
		if (i < 6) {
			da[i] = raw[i];
		} else if (i < 12) {
			sa[i - 6] = raw[i];
		} else if (i == 12) {
			proto = proto & 0x00FF;
			proto = proto | (((unsigned int)raw[i]) << 8);
		} else if (i == 13) {
			proto = proto & 0xFF00;
			proto = proto | (((unsigned int)raw[i]) << 0);
			i = 14;
			break;
		}
	}

	//TRACE();

	if (total_len > 19)
		new_sk = dev_alloc_skb(2 + total_len + 2);
	else
		new_sk = dev_alloc_skb(128);

	if (!new_sk) {
		//hmc_err("no space to allocate");
		pr_err("nl60211_util_gen_pkt() error, new_skb alloc failed\n");
		return;
	}

	skb_reserve(new_sk, 2);

	ether = (struct ethhdr *)skb_put(new_sk, ETH_HLEN);
	//memset(ether, 0, ETH_HLEN);

	memcpy(ether->h_dest, da, ETH_ALEN);
	memcpy(ether->h_source, sa, ETH_ALEN);
	ether->h_proto = ntohs(proto);

	if (total_len <= 14) {
		pos = skb_put(new_sk, 5);
		*pos++ = 100;
		*pos++ = 101;
		*pos++ = 102;
		*pos++ = 103;
		*pos++ = 104;
	} else {
		pos = skb_put(new_sk, total_len - 14);
		for (i = i; i < total_len; i++)
			*pos++ = raw[i];
	}

	skb_reset_mac_header(new_sk);

	//hmc_print_skb(new_sk, "nl60211_util_gen_pkt");

	switch (type) {
	case NL60211_SEND_PLC:
		egress = HMC_PORT_PLC;
		break;
	case NL60211_SEND_WIFI:
		egress = HMC_PORT_WIFI;
		break;
	case NL60211_SEND_FLOOD:
		egress = HMC_PORT_FLOOD;
		break;
	case NL60211_SEND_BEST:
		egress = HMC_PORT_BEST;
		break;
	}

	pdata->hmc_ops->xmit(new_sk, egress);
#endif
}

static void nl60211_util_plc_exp_time_reset(struct ak60211_if_data *ifmsh)
{
	struct ak60211_mesh_path *mpath;
	struct hlist_node *n;
	struct ak60211_mesh_table *tbl = ifmsh->mesh_paths;

	spin_lock_bh(&tbl->walk_lock);
	hlist_for_each_entry_safe(mpath, n, &tbl->walk_head, walk_list) {
		mpath->exp_time = jiffies;
		ifmsh->hmc_ops->path_update(mpath->dst,
			mpath->metric, mpath->sn, mpath->flags, HMC_PORT_PLC);
	}
	spin_unlock_bh(&tbl->walk_lock);
}

static void nl60211_util_simple_response(
	struct nl60211msg *nlreq,
	u32 payload_len,
	void *payload)
{
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	u32 nlmsgsize;
	int ret;

	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
			payload_len;
	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}
	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */
	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);
	memcpy(nlres->buf, payload, payload_len);
	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);
	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_util_debug_dump(struct nl60211msg *nlreq)
{
	pr_warn("====== NL60211 DUMP ======\n");
	pr_warn("magic number = %d\n", NL60211_VERSION);
	pr_warn("g_nl60211_ctrl_para.debugPrint = %d\n", g_nl60211_ctrl_para.debugPrint);
	pr_warn("pid_of_sender = %d\n", PID_OF_SENDER);
	pr_warn("pid_of_receiver = %d\n", pid_of_receiver);
	pr_warn("if_index = %u\n", IF_INDEX);
	pr_warn("command_type = 0x%04X\n", COMMAND_TYPE);
	pr_warn("is_nl60211_in_recv = %u\n", is_nl60211_in_recv);
	pr_warn("is_nl60211_in_recv_once = %u\n", is_nl60211_in_recv_once);
	pr_warn("recv_ether_type[0] = %u\n", recv_ether_type[0]);
	pr_warn("recv_ether_type[1] = %u\n", recv_ether_type[1]);
}

static void nl60211_cmd_ctrl_proc(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_ctrl_req *req =
		(struct nl60211_ctrl_req *)nlreq->buf;
	//response
	struct nl60211_ctrl_res res;

	res.return_code = 0;
	res.ctrl_code = req->ctrl_code;

	switch (req->ctrl_code) {
	case NL60211_CTRL_GET_VERSION:
		res.u.verNum = g_nl60211_ctrl_para.verNum;
		break;
	case NL60211_CTRL_DUMP_KERNEL_MSG:
		nl60211_util_debug_dump(nlreq);
		break;
	case NL60211_CTRL_GET_DEBUG_PRINT:
		res.u.debugPrint = g_nl60211_ctrl_para.debugPrint;
		break;
	case NL60211_CTRL_SET_DEBUG_PRINT:
		g_nl60211_ctrl_para.debugPrint = req->u.debugPrint;
		break;
	case NL60211_CTRL_GET_RECV_PORT_DETECT:
		res.u.recvPortDetect = g_nl60211_ctrl_para.recvPortDetect;
		break;
	case NL60211_CTRL_SET_RECV_PORT_DETECT:
		g_nl60211_ctrl_para.recvPortDetect = req->u.recvPortDetect;
		break;
	default:
		res.return_code = -1;
		break;
	}

	//response
	nl60211_util_simple_response(nlreq, sizeof(res), &res);
}

static void nl60211_cmd_getmeshid(struct nl60211msg *nlreq)
{
	//request
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_getmeshid_res *res;
	u32 nlmsgsize;
	s32 return_code = 0;
	int ret;
	//local
	u8 id[33];
	size_t id_len;

	plc_get_meshid(id, &id_len);

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_getmeshid_res) +
		    id_len + 1/* char: \'0 */;
	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);

	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}

	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);

	res = (struct nl60211_getmeshid_res *)nlres->buf;
	res->return_code = return_code;
	res->id_len = id_len;
	memcpy(res->id, id, id_len);
	res->id[id_len] = 0; /* char: \'0 , for C string. */

	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);

	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_cmd_setmeshid(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_setmeshid_req *req = (struct nl60211_setmeshid_req *)
					     nlreq->buf;
	//response
	struct nl60211_setmeshid_res simpleres;
	s32 return_code = 0;

	//request
	if (req->id_len > 32) {
		return_code = -1;
	} else {
		plc_set_meshid(req->id, req->id_len);
		return_code = 0;
	}

	//response
	simpleres.return_code = return_code;
	nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_recv(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_recv_req *req = (struct nl60211_recv_req *)nlreq->buf;
	//response
	//struct nl60211_recv_res simpleres;

	recv_ether_type[0] = req->ether_type[0];
	recv_ether_type[1] = req->ether_type[1];
	is_nl60211_in_recv = 1;
	pid_of_receiver = PID_OF_SENDER;

	pr_info("%s() start ...\n", __func__);

	//response
	//simpleres.return_code = 0;
	//nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_recv_once(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_recvonce_req *req = (struct nl60211_recvonce_req *)
					    nlreq->buf;
	//response
	//struct nl60211_recvonce_res simpleres;

	recv_ether_type[0] = req->ether_type[0];
	recv_ether_type[1] = req->ether_type[1];
	is_nl60211_in_recv_once = 1;
	pid_of_receiver = PID_OF_SENDER;

	pr_info("%s() start ...\n", __func__);

	//response
	//simpleres.return_code = 0;
	//nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_recv_cancel(struct nl60211msg *nlreq)
{
	//request
	//response
	struct nl60211_recvcancel_res simpleres;

	recv_ether_type[0] = 0;
	recv_ether_type[1] = 0;
	is_nl60211_in_recv = 0;
	is_nl60211_in_recv_once = 0;

	pr_info("%s() ...\n", __func__);

	//response
	simpleres.return_code = 0;
	nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_sendplc(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendplc_req *req = (struct nl60211_sendplc_req *)
					   nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (g_nl60211_ctrl_para.debugPrint) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	nl60211_util_gen_pkt(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type);

	//response
	{
		struct nl60211_sendplc_res simpleres;

		simpleres.return_code = 0;
		nl60211_util_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_sendwifi(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendwifi_req *req = (struct nl60211_sendwifi_req *)
					    nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (g_nl60211_ctrl_para.debugPrint) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	nl60211_util_gen_pkt(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type);

	//response
	{
		struct nl60211_sendwifi_res simpleres;

		simpleres.return_code = 0;
		nl60211_util_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_sendflood(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendflood_req *req = (struct nl60211_sendflood_req *)
					     nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (g_nl60211_ctrl_para.debugPrint) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	nl60211_util_gen_pkt(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type);

	//response
	{
		struct nl60211_sendflood_res simpleres;

		simpleres.return_code = 0;
		nl60211_util_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_sendbest(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendbest_req *req = (struct nl60211_sendbest_req *)
					    nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (g_nl60211_ctrl_para.debugPrint) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	nl60211_util_gen_pkt(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type);

	//response
	{
		struct nl60211_sendbest_res simpleres;

		simpleres.return_code = 0;
		nl60211_util_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_getsa(struct nl60211msg *nlreq)
{
	//request
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_getsa_res *res;
	u32 nlmsgsize;
	s32 return_code = 0;
	int ret;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	//local
	//temp

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
			sizeof(struct nl60211_getsa_res) + 6;
	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);

	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}

	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
						nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);

	res = (struct nl60211_getsa_res *)nlres->buf;
	res->return_code = return_code;
	res->sa_len = 6;
	memcpy(res->sa, pdata->addr, 6);

	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);

	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_cmd_addmpath(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_addmpath_req *req =
		(struct nl60211_addmpath_req *)nlreq->buf;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	int ret;
	//response
	struct nl60211_addmpath_res simpleres;
	s32 return_code = 0;

	if (!pdata->hmc_ops)
		return;

	//hmc_ops_fdb_insert
	ret = pdata->hmc_ops->fdb_insert(req->da, req->iface_id);

	//response
	if (ret < 0) {
		return_code = 1;
		pr_err("fdb_insert error, ret = %d\n", ret);
		pr_err("req->iface_id = %d\n", req->iface_id);
		pr_err("req->da[0] = 0x%02X\n", req->da[0]);
		pr_err("req->da[1] = 0x%02X\n", req->da[1]);
		pr_err("req->da[2] = 0x%02X\n", req->da[2]);
		pr_err("req->da[3] = 0x%02X\n", req->da[3]);
		pr_err("req->da[4] = 0x%02X\n", req->da[4]);
		pr_err("req->da[5] = 0x%02X\n", req->da[5]);
	}

	simpleres.return_code = return_code;
	nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_delmpath(struct nl60211msg *nlreq)
{
	//int br_hmc_path_del(const u8 *addr)
	//request
	struct nl60211_delmpath_req *req =
		(struct nl60211_delmpath_req *)nlreq->buf;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	int ret;
	//response
	//struct sk_buff *skbres;
	//struct nl60211msg *nlres;
	//struct nl60211_setmeshid_res *res;
	//u32 nlmsgsize;
	struct nl60211_delmpath_res simpleres;

	if (!pdata->hmc_ops)
		return;

	ret = pdata->hmc_ops->fdb_del(req->da, req->iface_id);

	simpleres.return_code = (s32)ret;
	nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_setmpath(struct nl60211msg *nlreq)
{
}

static void nl60211_cmd_getmpath(struct nl60211msg *nlreq)
{
	//struct hmc_path *br_hmc_path_lookup(const u8 *dst)
	//request
	struct nl60211_getmpath_req *req =
		(struct nl60211_getmpath_req *)nlreq->buf;
	struct hmc_fdb_entry f;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_getmpath_res *res;
	u32 nlmsgsize;
	int ret;

	if (!pdata->hmc_ops)
		return;

	ret = pdata->hmc_ops->fdb_lookup(&f, req->da, req->iface_id);

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_getmpath_res);
	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);

	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}

	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);

	res = (struct nl60211_getmpath_res *)nlres->buf;
	if (ret == 0) {
		res->return_code = 0;
		memcpy(res->da, f.addr, ETH_ALEN);
		res->iface_id = f.iface_id;
		res->sn = f.sn;
		res->metric = f.metric;
		res->flags = (u32)f.flags;
		res->exp_time = f.exp_time;
	} else {
		res->return_code = -1;
	}

	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);

	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_cmd_dumpmpath(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_mesh_info info[HMC_MAX_NODES] = {0};
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_dumpmpath_res *res;
	u32 nlmsgsize, i = 0;
	int ret, do_final_msg = 0;

	if (!pdata->hmc_ops) {
		pr_err("hmc_ops doesn't exist.\n");
		return;
	}

	//ref: hmc_ops_fdb_dump()
	if (pdata->hmc_ops->fdb_dump(info, HMC_MAX_NODES) < 0) {
		pr_err("info size is overflow\n");
		do_final_msg = 1;
	}
	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nl60211_util_plc_exp_time_reset(pdata);
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_dumpmpath_res);
	while (1) {
		if (do_final_msg == 0) {
			if (i >= HMC_MAX_NODES) {
				do_final_msg = 1;
			} else {
				if (info[i].iface_id == 0) {
					i++;
					continue;
				}
			}
		}
		skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
		if (!skbres) {
			pr_err("Failed to allocate new skb\n");
			return;
		}
		nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
						       nlmsgsize, 0);
		NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

		//copy input command to response
		nl60211_nlmsghdr_copy(nlres, nlreq);

		res = (struct nl60211_dumpmpath_res *)nlres->buf;
		if (do_final_msg) {
			res->return_code = -1;
		} else {
			res->return_code = 0;
			memcpy(res->da, info[i].dst, ETH_ALEN);
			res->iface_id = info[i].iface_id;
			res->sn = info[i].sn;
			res->metric = info[i].metric;
			res->flags = (u32)info[i].flags;
			//res->exp_time = info[i].exp_time;
		}

		//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
		ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);

		if (ret < 0) {
			pr_info("Error while sending back to user\n");
			return;
		}

		if (do_final_msg)
			break;
		i++;
	}
}

static void nl60211_cmd_plcgetmetric(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_plcgetmetric_req *req =
		(struct nl60211_plcgetmetric_req *)nlreq->buf;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	struct ak60211_mesh_path *mpath = NULL;
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_plcgetmetric_res *res;
	u32 nlmsgsize;
	int ret;

	//ret = pdata->hmc_ops->fdb_lookup(&f, req->da, req->iface_id);
	mpath = ak60211_mpath_lookup(pdata, req->da);

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nl60211_util_plc_exp_time_reset(pdata);
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_plcgetmetric_res);
	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}

	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);

	res = (struct nl60211_plcgetmetric_res *)nlres->buf;
	if (mpath) {
		res->return_code = 0;
		res->metric = mpath->metric;
	} else {
		res->return_code = -1;
	}

	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);

	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_cmd_plcsetmetric(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_plcsetmetric_req *req =
		(struct nl60211_plcsetmetric_req *)nlreq->buf;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	struct ak60211_mesh_path *mpath = NULL;
	//response
	struct nl60211_plcsetmetric_res simpleres;
	s32 return_code = 0;

	nl60211_util_plc_exp_time_reset(pdata);
	mpath = ak60211_mpath_lookup(pdata, req->da);

	//request
	if (mpath) {
		return_code = 0;
		mpath->metric = req->metric;
		pdata->hmc_ops->path_update(mpath->dst,
			mpath->metric, mpath->sn, mpath->flags, HMC_PORT_PLC);
	} else {
		return_code = -1;
	}

	//response
	simpleres.return_code = return_code;
	nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_plcgetmpara(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_plcgetmpara_req *req =
		(struct nl60211_plcgetmpara_req *)nlreq->buf;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_plcgetmpara_res *res;
	u32 nlmsgsize;
	int ret;
	s32 return_code = 0;

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_plcgetmpara_res);
	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}

	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);

	res = (struct nl60211_plcgetmpara_res *)nlres->buf;
	res->return_code = return_code;
	res->param_flags = req->param_flags;
	res->cfg.MeshRetryTimeout =
		pdata->mshcfg.MeshRetryTimeout;
	res->cfg.MeshConfirmTimeout =
		pdata->mshcfg.MeshConfirmTimeout;
	res->cfg.MeshHoldingTimeout =
		pdata->mshcfg.MeshHoldingTimeout;
	res->cfg.MeshMaxPeerLinks =
		pdata->mshcfg.MeshMaxPeerLinks;
	res->cfg.MeshMaxRetries =
		pdata->mshcfg.MeshMaxRetries;
	res->cfg.MeshTTL =
		pdata->mshcfg.MeshTTL;
	res->cfg.element_ttl =
		pdata->mshcfg.element_ttl;
	res->cfg.MeshHWMPmaxPREQretries =
		pdata->mshcfg.MeshHWMPmaxPREQretries;
	res->cfg.path_refresh_time =
		pdata->mshcfg.path_refresh_time;
	res->cfg.min_discovery_timeout =
		pdata->mshcfg.min_discovery_timeout;
	res->cfg.MeshHWMPactivePathTimeout =
		pdata->mshcfg.MeshHWMPactivePathTimeout;
	res->cfg.MeshHWMPpreqMinInterval =
		pdata->mshcfg.MeshHWMPpreqMinInterval;
	res->cfg.MeshHWMPperrMinInterval =
		pdata->mshcfg.MeshHWMPperrMinInterval;
	res->cfg.MeshHWMPnetDiameterTraversalTime =
		pdata->mshcfg.MeshHWMPnetDiameterTraversalTime;
	res->cfg.rssi_threshold =
		pdata->mshcfg.rssi_threshold;
	res->cfg.plink_timeout =
		pdata->mshcfg.plink_timeout;
	res->cfg.beacon_interval =
		pdata->mshcfg.beacon_interval;

	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);

	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_cmd_plcsetmpara(struct nl60211msg *nlreq)
{
	//request
	struct nl60211_plcsetmpara_req *req =
		(struct nl60211_plcsetmpara_req *)nlreq->buf;
	struct ak60211_if_data *pdata = ak60211_dev_to_ifdata();
	u32 mask = 0x00000001;
	//response
	struct nl60211_plcsetmpara_res simpleres;
	s32 return_code = 0;

	if (req->param_flags & mask)
		pdata->mshcfg.MeshRetryTimeout =
			req->cfg.MeshRetryTimeout;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshConfirmTimeout =
			req->cfg.MeshConfirmTimeout;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshHoldingTimeout =
			req->cfg.MeshHoldingTimeout;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshMaxPeerLinks =
			req->cfg.MeshMaxPeerLinks;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshMaxRetries =
			req->cfg.MeshMaxRetries;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshTTL =
			req->cfg.MeshTTL;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.element_ttl =
			req->cfg.element_ttl;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshHWMPmaxPREQretries =
			req->cfg.MeshHWMPmaxPREQretries;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.path_refresh_time =
			req->cfg.path_refresh_time;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.min_discovery_timeout =
			req->cfg.min_discovery_timeout;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshHWMPactivePathTimeout =
			req->cfg.MeshHWMPactivePathTimeout;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshHWMPpreqMinInterval =
			req->cfg.MeshHWMPpreqMinInterval;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshHWMPperrMinInterval =
			req->cfg.MeshHWMPperrMinInterval;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.MeshHWMPnetDiameterTraversalTime =
			req->cfg.MeshHWMPnetDiameterTraversalTime;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.rssi_threshold =
			req->cfg.rssi_threshold;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.plink_timeout =
			req->cfg.plink_timeout;
	if (req->param_flags & (mask <<= 1))
		pdata->mshcfg.beacon_interval =
			req->cfg.beacon_interval;

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	simpleres.return_code = return_code;
	nl60211_util_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_plcdumpsta(struct nl60211msg *nlreq)
{
	struct ak60211_if_data *plcdev = ak60211_dev_to_ifdata();
	struct ak60211_sta_info *sta, *tmp;

	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_plcdumpsta_res *res;
	u32 nlmsgsize;
	int ret;

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_plcdumpsta_res);

	mutex_lock(&plcdev->sta_mtx);
	list_for_each_entry_safe(sta, tmp, &plcdev->sta_list, list) {
		skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
		if (!skbres) {
			pr_err("Failed to allocate new skb\n");
			return;
		}
		nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
						       nlmsgsize, 0);
		NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */
		//copy input command to response
		nl60211_nlmsghdr_copy(nlres, nlreq);
		res = (struct nl60211_plcdumpsta_res *)nlres->buf;
		res->return_code = 0;
		res->plink_state = (u32)sta->plink_state;
		res->llid = sta->llid;
		res->plid = sta->plid;
		memcpy(res->addr, sta->addr, sizeof(res->addr));
		//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
		ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);
		if (ret < 0) {
			pr_info("Error while sending back to user\n");
			return;
		}
	}
	mutex_unlock(&plcdev->sta_mtx);

	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}
	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */
	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);
	res = (struct nl60211_plcdumpsta_res *)nlres->buf;
	res->return_code = -1;
	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);
	if (ret < 0) {
		pr_info("Error while sending back to user\n");
		return;
	}
}

static void nl60211_cmd_plcdumpmpath(struct nl60211msg *nlreq)
{
	struct ak60211_if_data *ifmsh = ak60211_dev_to_ifdata();
	struct ak60211_mesh_path *mpath;
	struct hlist_node *n;
	struct ak60211_mesh_table *tbl = ifmsh->mesh_paths;

	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_plcdumpmpath_res *res;
	u32 nlmsgsize;
	int ret;

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	nl60211_util_plc_exp_time_reset(ifmsh);
	nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
		    sizeof(struct nl60211_plcdumpmpath_res);
	spin_lock_bh(&tbl->walk_lock);
	hlist_for_each_entry_safe(mpath, n, &tbl->walk_head, walk_list) {
		skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
		if (!skbres) {
			pr_err("Failed to allocate new skb\n");
			return;
		}
		nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
						       nlmsgsize, 0);
		NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */
		//copy input command to response
		nl60211_nlmsghdr_copy(nlres, nlreq);
		res = (struct nl60211_plcdumpmpath_res *)nlres->buf;
		res->return_code = 0;
		memcpy(res->da, mpath->dst, ETH_ALEN);
		memcpy(res->next_hop, mpath->next_hop->addr, ETH_ALEN);
		res->sn = mpath->sn;
		res->metric = mpath->metric;
		res->hop_count = mpath->hop_count;
		res->exp_time = mpath->exp_time;
		res->discovery_timeout = mpath->discovery_timeout;
		res->discovery_retries = mpath->discovery_retries;
		res->flags = (u32)mpath->flags;
		res->is_root = (u32)mpath->is_root;
		ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);
		if (ret < 0) {
			pr_info("Error while sending back to user\n");
			return;
		}
	}
	spin_unlock_bh(&tbl->walk_lock);

	skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
	if (!skbres) {
		pr_err("Failed to allocate new skb\n");
		return;
	}
	nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
					       nlmsgsize, 0);
	NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */
	//copy input command to response
	nl60211_nlmsghdr_copy(nlres, nlreq);
	res = (struct nl60211_plcdumpmpath_res *)nlres->buf;
	res->return_code = -1;
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);
	if (ret < 0) {
		pr_info("Error while sending back to user\n");
		return;
	}
}

static int nl60211_rx_callback_proto_filter(size_t len, u8 *data, unsigned int cmd_type)
{
	struct sk_buff *skb_res;
	struct nl60211msg *snap_res;
	unsigned int msg_size;
	struct nl60211_recv_res *res_payload;
	int ret;

	msg_size = sizeof(struct nl60211msg) - sizeof(snap_res->buf) + sizeof(
		struct nl60211_recv_res) + len;

	skb_res = nlmsg_new(msg_size, GFP_ATOMIC);
	if (!skb_res) {
		pr_err("Failed to allocate new skb\n");
		is_nl60211_in_recv = 0;
		is_nl60211_in_recv_once = 0;
		return -1;
	}

	snap_res = (struct nl60211msg *)nlmsg_put(skb_res, 0, 0, NLMSG_DONE,
			msg_size,
			0);
	NETLINK_CB(skb_res).dst_group = 0; /* not in mcast group */

	//copy input command to response
	snap_res->nl_msghdr.nlmsg_type = cmd_type;
	snap_res->if_index = if_index_recv;

	res_payload = (struct nl60211_recv_res *)snap_res->buf;
	res_payload->return_code = 0;
	res_payload->recv_len = len;
	memcpy(res_payload->recv_buf, data, len);

	ret = nlmsg_unicast(nl_sk, skb_res, pid_of_receiver);

	if (ret < 0)
		pr_info("Error while sending back to user\n");

	return 0;
}

int nl60211_rx_callback(struct sk_buff *skb)
{
	size_t len, i;
	u8 *data;

	data = (u8 *)skb_mac_header(skb);
	//data = (u8 *) skb->head;

	if (skb_is_nonlinear(skb))
		len = skb->data_len;
	else
		len = skb->len;

	if (is_nl60211_in_recv == 0 && is_nl60211_in_recv_once == 0)
		return 0;

	do {
		unsigned int cmd_type;
		//pr_err("nl60211 rx, dev name = %s\n", skb->dev->name);
		//if (len < 46)
		//	break;
		//if (len > 1500)
		//	break;
		//if (data[12] != recv_ether_type[0])
		//	break;
		//if (data[13] != recv_ether_type[1])
		//	break;
		//match
		is_nl60211_in_recv_once = 0;
		pr_info("[SNAP RX] ether_type = %02X %02X, len = %ld\n",
			data[12],
			data[13],
			len);
		if (g_nl60211_ctrl_para.debugPrint) {
			for (i = 14; i < len; i++) {
				pr_info("[SNAP RX] 0x%02X\n", data[i]);
				if (i >= 17)
					break;
			}
		}
		cmd_type = command_type_recv;
		if (g_nl60211_ctrl_para.recvPortDetect) {
			if (strcmp(skb->dev->name, "mesh0") == 0)
				cmd_type = NL60211_RECV_WIFI;
			else
				cmd_type = NL60211_RECV_PLC;
		}
		nl60211_rx_callback_proto_filter(len + skb->mac_len, data, cmd_type);
		return 0;
	} while (0);

	return 0;
}
EXPORT_SYMBOL(nl60211_rx_callback);

static void nl60211_netlink_input(struct sk_buff *skb_in)
{
	struct nl60211msg *nlreq;
	struct nlmsghdr *nlh;

	// parsing request
	nlh = (struct nlmsghdr *)skb_in->data;
	nlreq = (struct nl60211msg *)skb_in->data;

	if (g_nl60211_ctrl_para.debugPrint) {
		pr_info("\nEntering: %s\n", __func__);
		pr_info("skb_in: len=%d, data_len=%d, mac_len=%d\n",
			skb_in->len, skb_in->data_len, skb_in->mac_len);
		pr_info("skb_in          = %p\n", skb_in);
		pr_info("skb_in->data    = %p\n", skb_in->data);
		pr_info("nlh             = %p\n", nlh);
		pr_info("nlmsg_data(nlh) = %p\n", nlmsg_data(nlh));
		pr_info("nlh->nlmsg_len   = %d\n", nlh->nlmsg_len);
		pr_info("nlh->nlmsg_type  = %d\n", nlh->nlmsg_type);
		pr_info("nlh->nlmsg_flags = %d\n", nlh->nlmsg_flags);
		pr_info("nlh->nlmsg_seq   = %d\n", nlh->nlmsg_seq);
		pr_info("nlh->nlmsg_pid   = %d\n", nlh->nlmsg_pid);
		//pr_info("user_data[0]     = %d\n", snap_req->buf[0]);
		//pr_info("user_data[1]     = %d\n", snap_req->buf[1]);
		//pr_info("user_data[2]     = %d\n", snap_req->buf[2]);
		pr_info("if_index     = %d\n", nlreq->if_index);
	}

	switch (nlh->nlmsg_type & NL60211_CMD_MASK) {
	case NL60211_CTRL:
		nl60211_cmd_ctrl_proc(nlreq);
		break;
	case NL60211_GETMESHID:
		nl60211_cmd_getmeshid(nlreq);
		break;
	case NL60211_SETMESHID:
		nl60211_cmd_setmeshid(nlreq);
		break;
	case NL60211_RECV:
		if_index_recv = IF_INDEX;
		command_type_recv = COMMAND_TYPE;
		nl60211_cmd_recv(nlreq);
		break;
	case NL60211_RECV_ONCE:
		if_index_recv = IF_INDEX;
		command_type_recv = COMMAND_TYPE;
		nl60211_cmd_recv_once(nlreq);
		break;
	case NL60211_RECV_CANCEL:
		nl60211_cmd_recv_cancel(nlreq);
		break;
	case NL60211_SEND_PLC:
		nl60211_cmd_sendplc(nlreq);
		break;
	case NL60211_SEND_WIFI:
		nl60211_cmd_sendwifi(nlreq);
		break;
	case NL60211_SEND_FLOOD:
		nl60211_cmd_sendflood(nlreq);
		break;
	case NL60211_SEND_BEST:
		nl60211_cmd_sendbest(nlreq);
		break;
	case NL60211_GETSA:
		nl60211_cmd_getsa(nlreq);
		break;
	case NL60211_ADD_MPATH:
		nl60211_cmd_addmpath(nlreq);
		break;
	case NL60211_DEL_MPATH:
		nl60211_cmd_delmpath(nlreq);
		break;
	case NL60211_SET_MPATH:
		nl60211_cmd_setmpath(nlreq);
		break;
	case NL60211_GET_MPATH:
		nl60211_cmd_getmpath(nlreq);
		break;
	case NL60211_DUMP_MPATH:
		nl60211_cmd_dumpmpath(nlreq);
		break;
	case NL60211_PLC_GET_METRIC:
		nl60211_cmd_plcgetmetric(nlreq);
		break;
	case NL60211_PLC_SET_METRIC:
		nl60211_cmd_plcsetmetric(nlreq);
		break;
	case NL60211_PLC_GET_MPARA:
		nl60211_cmd_plcgetmpara(nlreq);
		break;
	case NL60211_PLC_SET_MPARA:
		nl60211_cmd_plcsetmpara(nlreq);
		break;
	case NL60211_PLC_DUMP_STA:
		nl60211_cmd_plcdumpsta(nlreq);
		break;
	case NL60211_PLC_DUMP_MPATH:
		nl60211_cmd_plcdumpmpath(nlreq);
		break;
	default:
		pr_warn("[NL60211] Unknown command = %d\n", nlh->nlmsg_type);
	}
}

struct netlink_kernel_cfg nl60211_netlink_cfg = {
	.input = nl60211_netlink_input,
};

int test_br_hmc_rx_snap(struct sk_buff *skb)
{
	//br_hmc_print_skb(skb, "test_br_hmc_rx_snap", 0);
	nl60211_rx_callback(skb);
	return 0;
}

int nl60211_netlink_init(void)
{
	pr_info("Entering: %s\n", __func__);
	//This is for 3.6 kernels and above.

	nl_sk = netlink_kernel_create(
		&init_net,
		NETLINK_60211,
		&nl60211_netlink_cfg);

	if (!nl_sk) {
		pr_alert("Error creating socket.\n");
		return -10;
	}

	return 0;
}

void nl60211_netlink_exit(void)
{
	pr_info("exiting snap module\n");
	if (nl_sk)
		netlink_kernel_release(nl_sk);
}

