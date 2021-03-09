#define IN_JETSON (1)

#if IN_JETSON
#include "nl60211.h"
#include "../hmc/hmc.h"
#include "mac60211.h"
#include "ak60211_mesh_private.h"
#endif

#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

//
//ref: netlink.h
//
#define NETLINK_60211 (MAX_LINKS - 1)
// nlmsg_type[15:8] is snap command flag
#define NL60211FLAG_NO_RESPONSE 0x8000
// nlmsg_type[7:0] is snap command enum
enum {
	NL60211_DEBUG = 0,       // a.out debug       br0 ...
	NL60211_GETMESHID,     // a.out getmeshid   br0
	NL60211_SETMESHID,     // a.out setmeshid   br0 mymesh0
	NL60211_RECV,          // a.out recv        br0 AA 66
	NL60211_RECV_ONCE,     // a.out recvonce    br0 AA 66
	NL60211_RECV_CANCEL,   // a.out recvcancel  br0
	NL60211_SEND_PLC,      // a.out sendplc     br0 [da] [sa] [eth type] ...
	NL60211_SEND_WIFI,     // a.out sendwifi    br0 [da] [sa] [eth type] ...
	NL60211_SEND_FLOOD,    // a.out sendflood   br0 [da] [sa] [eth type] ...
	NL60211_SEND_BEST,     // a.out sendbest    br0 [da] [sa] [eth type] ...
	NL60211_GETSA,         // a.out getsa       br0

	NL60211_ADD_MPATH,     // a.out addmpath    br0 [da] [if]
	NL60211_DEL_MPATH,     // a.out delmpath    br0 [da] [if]
	NL60211_SET_MPATH,     // reserved
	NL60211_GET_MPATH,     // a.out getmpath    br0 [da] [if]
	NL60211_DUMP_MPATH,    // a.out dumpmpath   br0

	NL60211_PLC_GET_METRIC, // a.out plcgetmetric br0 [da]
	NL60211_PLC_SET_METRIC, // a.out plcsetmetric br0 [da] [metric]
	NL60211_PLC_STA_DUMP,   // a.out plcstadump   br0
	NL60211_PLC_GET_MPARA,  // a.out plcgetmpara  br0 mpara_flag
	NL60211_PLC_SET_MPARA,  // a.out plcsetmpara  br0 mpara_flag value
};

// from private structure: ak60211_mesh_config
struct plc_mesh_config {
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

// inside nl60211msg.buf
// response
struct nl60211_debug_res {
	s32    return_code;
	u32    len;
	char   buf[];
};

struct nl60211_getmeshid_res {
	s32    return_code;
	u32    id_len;
	char   id[];
};

struct nl60211_setmeshid_res {
	s32    return_code;
};

struct nl60211_recv_res {
	s32    return_code;
	u32    recv_len;
	u8     recv_buf[];
};

struct nl60211_recvonce_res {
	s32    return_code;
	u32    recv_len;
	u8     recv_buf[];
};

struct nl60211_recvcancel_res {
	s32    return_code;
};

struct nl60211_sendplc_res {
	s32    return_code;
};

struct nl60211_sendwifi_res {
	s32    return_code;
};

struct nl60211_sendflood_res {
	s32    return_code;
};

struct nl60211_sendbest_res {
	s32    return_code;
};

struct nl60211_getsa_res {
	s32    return_code;
	u32    sa_len;
	u8     sa[];
};

struct nl60211_addmpath_res {
	s32    return_code;
};

struct nl60211_delmpath_res {
	s32    return_code;
};

struct nl60211_setmpath_res {
	s32    return_code;
};

struct nl60211_getmpath_res {
	s32    return_code;
	u8     da[ETH_ALEN];
	u16    iface_id;
	u32    sn;
	u32    metric;
	u32    flags;
	unsigned long exp_time;
};

struct nl60211_dumpmpath_res {
	s32    return_code;
	u8     da[ETH_ALEN];
	u16    iface_id;
	u32    sn;
	u32    metric;
	u32    flags;
	unsigned long exp_time;
};

struct nl60211_plcgetmetric_res {
	s32    return_code;
	u32    metric;
};

struct nl60211_plcsetmetric_res {
	s32    return_code;
};

// refer to struct plc_sta_info
struct nl60211_plcstadump_res {
	s32    return_code;
	u8     addr[ETH_ALEN];
	u32    plink_state;
	u16    llid;
	u16    plid;
};

struct nl60211_plcgetmpara_res {
	s32    return_code;
	u32    param_flags;
	struct plc_mesh_config cfg;
};

struct nl60211_plcsetmpara_res {
	s32    return_code;
};

// request
struct nl60211_debug_req {
	u32    len;
	u8     buf[];
};

struct nl60211_getmeshid_req {
};

struct nl60211_setmeshid_req {
	u32    id_len;
	char   id[];
};

struct nl60211_recv_req {
	u8     ether_type[2];
};

struct nl60211_recvonce_req {
	u8     ether_type[2];
};

struct nl60211_recvcancel_req {
};

struct nl60211_sendplc_req {
	u32    total_len;
	u8     da[6];
	u8     sa[6];
	u8     ether_type[2];
	u8     payload[];
};

struct nl60211_sendwifi_req {
	u32    total_len;
	u8     da[6];
	u8     sa[6];
	u8     ether_type[2];
	u8     payload[];
};

struct nl60211_sendflood_req {
	u32    total_len;
	u8     da[6];
	u8     sa[6];
	u8     ether_type[2];
	u8     payload[];
};

struct nl60211_sendbest_req {
	u32    total_len;
	u8     da[6];
	u8     sa[6];
	u8     ether_type[2];
	u8     payload[];
};

struct nl60211_getsa_req {
};

struct nl60211_addmpath_req {
	u8     da[ETH_ALEN];
	u16    iface_id;
};

struct nl60211_delmpath_req {
	u8     da[ETH_ALEN];
	u16    iface_id;
};

struct nl60211_setmpath_req {
};

struct nl60211_getmpath_req {
	u8     da[ETH_ALEN];
	u16    iface_id;
};

struct nl60211_dumpmpath_req {
};

struct nl60211_plcgetmetric_req {
	u8     da[ETH_ALEN];
};

struct nl60211_plcsetmetric_req {
	u8     da[ETH_ALEN];
	u32    metric;
};

struct nl60211_plcstadump_req {
};

struct nl60211_plcgetmpara_req {
	u32    param_flags;
};

struct nl60211_plcsetmpara_req {
	u32    param_flags;
	struct plc_mesh_config cfg;
};

#define MAX_PAYLOAD 2048 /* maximum payload size for request&response */

// This buffer is for tx & "rx".
// And it contains socket message header:"struct msghdr" for simplifying.
struct nl60211msg {
	struct nlmsghdr     nl_msghdr;
	// netlink payload start
	unsigned int        if_index;
	char                buf[MAX_PAYLOAD];
	// netlink payload end
};

void test_hmc_gen_pkt_snap(
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

	if (!pdata->hmc_ops)
		return;

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

	//hmc_print_skb(new_sk, "test_hmc_gen_pkt_snap");

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
		egress = HMC_PORT_FLOOD;
		break;
	}

	pdata->hmc_ops->xmit(new_sk, egress);
#endif
}

#define PID_OF_SENDER  nlreq->nl_msghdr.nlmsg_pid
#define IF_INDEX       nlreq->if_index
#define COMMAND_TYPE   nlreq->nl_msghdr.nlmsg_type

static struct sock *nl_sk;
static int pr_debug_en;
static int pid_of_receiver;
static unsigned int if_index_recv;
static unsigned int command_type_recv;
static unsigned int is_nl60211_in_recv;
static unsigned int is_nl60211_in_recv_once;
static unsigned char recv_ether_type[2];

static void nl60211_cmd_simple_response(
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
	nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
	nlres->if_index = nlreq->if_index;
	memcpy(nlres->buf, payload, payload_len);
	//nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
	ret = nlmsg_unicast(nl_sk, skbres, PID_OF_SENDER);
	if (ret < 0)
		pr_info("Error while sending back to user\n");
}

static void nl60211_cmd_debug_dump(struct nl60211msg *nlreq)
{
	pr_warn("====== SNAP DUMP ======\n");
	pr_warn("magic number = %d\n", 124);
	pr_warn("pr_debug_en = %d\n", pr_debug_en);
	pr_warn("pid_of_sender = %d\n", PID_OF_SENDER);
	pr_warn("pid_of_receiver = %d\n", pid_of_receiver);
	pr_warn("if_index = %u\n", IF_INDEX);
	pr_warn("command_type = 0x%04X\n", COMMAND_TYPE);
	pr_warn("is_nl60211_in_recv = %u\n", is_nl60211_in_recv);
	pr_warn("is_nl60211_in_recv_once = %u\n", is_nl60211_in_recv_once);
	pr_warn("recv_ether_type[0] = %u\n", recv_ether_type[0]);
	pr_warn("recv_ether_type[1] = %u\n", recv_ether_type[1]);
}

static void nl60211_cmd_debug(struct nl60211msg *nlreq)
{
	enum {
		SET_DEBUG_PRINT = 0,
	};
	//request
	struct nl60211_debug_req *req =
		(struct nl60211_debug_req *)nlreq->buf;
	//response
	//struct sk_buff *skbres;
	//struct nl60211msg *nlres;
	//struct nl60211_debug_res *res;
	struct nl60211_debug_res simpleres;
	//u32 nlmsgsize;
	s32 return_code = 0;
	//int ret;
	//local

	//request
	do {
		if (req->len == 0) {
			simpleres.return_code = return_code;
			simpleres.len = 0;
			nl60211_cmd_debug_dump(nlreq);

			//response
			nl60211_cmd_simple_response(
				nlreq,
				sizeof(simpleres),
				&simpleres);
			return;
		}
		simpleres.return_code = return_code;
		simpleres.len = 0;
		switch (req->buf[0]) {
		case SET_DEBUG_PRINT:
			if (req->len >= 2) {
				pr_debug_en = req->buf[1];
				nl60211_cmd_debug_dump(nlreq);
				nl60211_cmd_simple_response(
					nlreq,
					sizeof(simpleres),
					&simpleres);
				return;
			}
			break;
		}
		return_code = -1;
	} while (0);

	//response
	simpleres.return_code = return_code;
	simpleres.len = 0;
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
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
	nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
	nlres->if_index = nlreq->if_index;

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
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
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
	//nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
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
	//nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
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
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_sendplc(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendplc_req *req = (struct nl60211_sendplc_req *)
					   nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (pr_debug_en) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	test_hmc_gen_pkt_snap(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type & 0x00FF);

	//response
	{
		struct nl60211_sendplc_res simpleres;

		simpleres.return_code = 0;
		nl60211_cmd_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_sendwifi(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendwifi_req *req = (struct nl60211_sendwifi_req *)
					    nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (pr_debug_en) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	test_hmc_gen_pkt_snap(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type & 0x00FF);

	//response
	{
		struct nl60211_sendwifi_res simpleres;

		simpleres.return_code = 0;
		nl60211_cmd_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_sendflood(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendflood_req *req = (struct nl60211_sendflood_req *)
					     nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (pr_debug_en) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	test_hmc_gen_pkt_snap(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type & 0x00FF);

	//response
	{
		struct nl60211_sendflood_res simpleres;

		simpleres.return_code = 0;
		nl60211_cmd_simple_response(nlreq, sizeof(simpleres),
					    &simpleres);
	}
}

static void nl60211_cmd_sendbest(struct nl60211msg *nlreq)
{
	unsigned int i;
	struct nl60211_sendbest_req *req = (struct nl60211_sendbest_req *)
					    nlreq->buf;
	unsigned char *req_rawdata = req->da;

	if (pr_debug_en) {
		for (i = 0; i < req->total_len; i++) {
			pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i,
				(unsigned int)req_rawdata[i],
				(unsigned int)req_rawdata[i]);
		}
	}

	test_hmc_gen_pkt_snap(req->total_len, req_rawdata,
			      nlreq->nl_msghdr.nlmsg_type & 0x00FF);

	//response
	{
		struct nl60211_sendbest_res simpleres;

		simpleres.return_code = 0;
		nl60211_cmd_simple_response(nlreq, sizeof(simpleres),
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
	nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
	nlres->if_index = nlreq->if_index;

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

	ret = pdata->hmc_ops->fdb_insert(req->da, req->iface_id);

	//response
	if (ret < 0) {
		return_code = 1;
		pr_err("req->iface_id = %d\n", req->iface_id);
		pr_err("req->da[0] = 0x%02X\n", req->da[0]);
		pr_err("req->da[1] = 0x%02X\n", req->da[1]);
		pr_err("req->da[2] = 0x%02X\n", req->da[2]);
		pr_err("req->da[3] = 0x%02X\n", req->da[3]);
		pr_err("req->da[4] = 0x%02X\n", req->da[4]);
		pr_err("req->da[5] = 0x%02X\n", req->da[5]);
	}

	simpleres.return_code = return_code;
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
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
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
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
	nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
	nlres->if_index = nlreq->if_index;

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

	if (!pdata->hmc_ops)
		return;

	if (pdata->hmc_ops->fdb_dump(info, HMC_MAX_NODES) < 0) {
		pr_err("info size is overflow\n");
		do_final_msg = 1;
	}
	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
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

		nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
			    sizeof(struct nl60211_dumpmpath_res);
		skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
		if (!skbres) {
			pr_err("Failed to allocate new skb\n");
			return;
		}

		nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
						       nlmsgsize, 0);
		NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

		//copy input command to response
		nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
		nlres->if_index = nlreq->if_index;

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
	nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
	nlres->if_index = nlreq->if_index;

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

	mpath = ak60211_mpath_lookup(pdata, req->da);

	//request
	if (mpath) {
		return_code = 0;
		mpath->metric = req->metric;
	} else {
		return_code = -1;
	}

	//response
	simpleres.return_code = return_code;
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_plcstadump(struct nl60211msg *nlreq)
{
	//request
	struct plc_sta_info infos[32] = {0};
	//response
	struct sk_buff *skbres;
	struct nl60211msg *nlres;
	struct nl60211_plcstadump_res *res;
	u32 nlmsgsize;
	int ret, do_final_msg = 0;
	size_t info_num;
	size_t i = 0;

	plc_sta_dump((struct plc_sta_info **)&infos, &info_num);

	//response
	if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
		return;
	while (1) {
		if (do_final_msg == 0) {
			if (i >= info_num)
				do_final_msg = 1;
		}

		nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) +
			    sizeof(struct nl60211_plcstadump_res);
		skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
		if (!skbres) {
			pr_err("Failed to allocate new skb\n");
			return;
		}

		nlres = (struct nl60211msg *)nlmsg_put(skbres, 0, 0, NLMSG_DONE,
						       nlmsgsize, 0);
		NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

		//copy input command to response
		nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
		nlres->if_index = nlreq->if_index;

		res = (struct nl60211_plcstadump_res *)nlres->buf;
		if (do_final_msg) {
			res->return_code = -1;
		} else {
			res->return_code = 0;
			res->plink_state = infos[i].plink_state;
			res->llid = infos[i].llid;
			res->plid = infos[i].plid;
			memcpy(res->addr, infos[i].addr, sizeof(res->addr));
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
	nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
	nlres->if_index = nlreq->if_index;

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
	nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static int nl60211_rx_callback_proto_filter(size_t len, u8 *data)
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
	snap_res->nl_msghdr.nlmsg_type = command_type_recv;
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
		if (len < 46)
			break;
		if (len > 1500)
			break;
		if (data[12] != recv_ether_type[0])
			break;
		if (data[13] != recv_ether_type[1])
			break;
		//match
		is_nl60211_in_recv_once = 0;
		pr_info("[SNAP RX] ether_type = %02X %02X, len = %ld\n",
			data[12],
			data[13],
			len);
		if (pr_debug_en) {
			for (i = 14; i < len; i++) {
				pr_info("[SNAP RX] 0x%02X\n", data[i]);
				if (i >= 17)
					break;
			}
		}
		nl60211_rx_callback_proto_filter(len + skb->mac_len, data);
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

	pr_info("\nEntering: %s\n", __func__);
	if (pr_debug_en) {
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

	switch (nlh->nlmsg_type & 0x00FF) {
	case NL60211_DEBUG:
		nl60211_cmd_debug(nlreq);
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
	case NL60211_PLC_STA_DUMP:
		nl60211_cmd_plcstadump(nlreq);
		break;
	case NL60211_PLC_GET_MPARA:
		nl60211_cmd_plcgetmpara(nlreq);
		break;
	case NL60211_PLC_SET_MPARA:
		nl60211_cmd_plcsetmpara(nlreq);
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

