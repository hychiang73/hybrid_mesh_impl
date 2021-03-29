// SPDX-License-Identifier: GPL-2.0-only
/*Copyright (C) 2021 AkiraNET Corporation */

#ifndef NL60211_UAPI_H
#define NL60211_UAPI_H

#include <linux/netlink.h>
#include <linux/types.h>

#define NL60211_DATA_STRUCT_VER 0x03
#define NL60211_SUB_VER         0x000A
#define NL60211_VERSION ((NL60211_DATA_STRUCT_VER<<16)|NL60211_SUB_VER)

#ifndef u8
typedef uint8_t u8;
#endif
#ifndef u16
typedef uint16_t u16;
#endif
#ifndef u32
typedef uint32_t u32;
#endif
#ifndef u64
typedef uint64_t u64;
#endif

#ifndef s8
typedef int8_t s8;
#endif
#ifndef s16
typedef int16_t s16;
#endif
#ifndef s32
typedef int32_t s32;
#endif
#ifndef s64
typedef int64_t s64;
#endif

//
//ref: netlink.h
//
#define NETLINK_60211 (MAX_LINKS - 1)
// nlmsg_type[15:12] is snap command flag
#define NL60211FLAG_NO_RESPONSE 0x8000
// nlmsg_type[11:0] is snap command enum
#define NL60211_CMD_MASK 0x0FFF
enum {
	NL60211_CTRL = 0,      // a.out ctrl        br0 ...
	NL60211_GETMESHID,     // a.out getmeshid   br0
	NL60211_SETMESHID,     // a.out setmeshid   br0 mymesh0
	NL60211_GETSA,         // a.out getsa       br0

	NL60211_RECV_MASK = 0x0100,
	NL60211_RECV,          // a.out recv        br0 AA 66
	NL60211_RECV_ONCE,     // a.out recvonce    br0 AA 66
	NL60211_RECV_CANCEL,   // a.out recvcancel  br0
	NL60211_RECV_PLC,      // ONLY used in response!!
	NL60211_RECV_WIFI,     // ONLY used in response!!

	NL60211_SEND_MASK = 0x0200,
	NL60211_SEND_PLC,      // a.out sendplc     br0 [da] [sa] [eth type] ...
	NL60211_SEND_WIFI,     // a.out sendwifi    br0 [da] [sa] [eth type] ...
	NL60211_SEND_FLOOD,    // a.out sendflood   br0 [da] [sa] [eth type] ...
	NL60211_SEND_BEST,     // a.out sendbest    br0 [da] [sa] [eth type] ...

	NL60211_HMC_MASK = 0x0300,
	NL60211_ADD_MPATH,     // a.out addmpath    br0 [da] [if]
	NL60211_DEL_MPATH,     // a.out delmpath    br0 [da] [if]
	NL60211_SET_MPATH,     // reserved
	NL60211_GET_MPATH,     // a.out getmpath    br0 [da] [if]
	NL60211_DUMP_MPATH,    // a.out dumpmpath   br0
	NL60211_DUMP_MPATH2,   // a.out dumpmpath2  br0

	NL60211_PLC_MASK = 0x0400,
	NL60211_PLC_GET_METRIC, // a.out plcgetmetric br0 [da]
	NL60211_PLC_SET_METRIC, // a.out plcsetmetric br0 [da] [metric]
	NL60211_PLC_GET_MPARA,  // a.out plcgetmpara  br0 mpara_flag
	NL60211_PLC_SET_MPARA,  // a.out plcsetmpara  br0 mpara_flag value
	NL60211_PLC_DUMP_STA,   // a.out plcdumpsta   br0
	NL60211_PLC_DUMP_STA2,  // a.out plcdumpsta2  br0
	NL60211_PLC_DUMP_MPATH, // a.out plcdumpmpath  br0
	NL60211_PLC_DUMP_MPATH2,// a.out plcdumpmpath2 br0

	NL60211_WIFI_MASK = 0x0500,
	NL60211_DUMP_WIFI_AP_RSSI, //TODO
};


// from private structure: ak60211_mesh_config
struct nl60211_plc_mesh_config {
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

struct nl60211_plcgetmpara_res {
	s32    return_code;
	u32    param_flags;
	struct nl60211_plc_mesh_config cfg;
};

struct nl60211_plcsetmpara_res {
	s32    return_code;
};

struct nl60211_plcdumpsta_res {
	s32    return_code;
	u8     addr[ETH_ALEN];
	u32    plink_state;
	u16    llid;
	u16    plid;
};

// ref: struct ak60211_mesh_path
struct nl60211_plcdumpmpath_res {
	s32    return_code;
	u8     da[ETH_ALEN];
	u8     next_hop[ETH_ALEN];
	u32    sn;
	u32    metric;
	u8     hop_count;
	unsigned long exp_time;
	u32    discovery_timeout;
	u8     discovery_retries;
	u32    flags;
	u32    is_root;
};

// request
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

struct nl60211_plcgetmpara_req {
	u32    param_flags;
};

struct nl60211_plcsetmpara_req {
	u32    param_flags;
	struct nl60211_plc_mesh_config cfg;
};

struct nl60211_plcdumpsta_req {
};

struct nl60211_plcdumpmpath_req {
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

enum {
	NL60211_CTRL_GET_VERSION = 0,
	NL60211_CTRL_DUMP_KERNEL_MSG,
	NL60211_CTRL_GET_DEBUG_PRINT,
	NL60211_CTRL_SET_DEBUG_PRINT,
	NL60211_CTRL_GET_RECV_PORT_DETECT,
	NL60211_CTRL_SET_RECV_PORT_DETECT,

	NL60211_CTRL_SELF_TEST_001 = 1001, //local test
	NL60211_CTRL_SELF_TEST_002, // echo mode
	NL60211_CTRL_SELF_TEST_003, // link test
	NL60211_CTRL_SELF_TEST_004, // local + link test
};

struct nl60211_ctrl_para {
	u32 verNum;
	u8 debugPrint;     // 0 or 1
	u8 recvPortDetect; // 0 or 1
	
};

union nl60211_ctrl_para_access {
	u32 verNum;
	u8 debugPrint;     // 0 or 1
	u8 recvPortDetect; // 0 or 1
};

struct nl60211_ctrl_res {
	s32    return_code;
	u32    ctrl_code;
	union nl60211_ctrl_para_access u;
};

struct nl60211_ctrl_req {
	u32    ctrl_code;
	union nl60211_ctrl_para_access u;
};

#endif /* NL60211_UAPI_H */
