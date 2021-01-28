#define IN_JETSON (1)

#if IN_JETSON
#include "nl60211.h"
#include "../bridge/br_hmc.h"
#endif

//Taken from https://stackoverflow.com/questions/15215865/netlink-sockets-in-c-using-the-3-x-linux-kernel?lq=1

#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>



//
//ref: netlink.h
//
#define NETLINK_60211 (MAX_LINKS-1)
// nlmsg_type[15:8] is snap command flag
#define NL60211FLAG_NO_RESPONSE 0x8000
// nlmsg_type[7:0] is snap command enum
enum {
    NL60211_DEBUG=0,       // snap debug       br0 ...
    NL60211_GETMESHID,     // snap getmeshid   br0
    NL60211_SETMESHID,     // snap setmeshid   br0 mymesh0
    NL60211_RECV,          // snap recv        br0
    NL60211_RECV_ONCE,     // snap recvonce    br0
    NL60211_RECV_CANCEL,   // snap recvcancel  br0
    NL60211_SEND_PLC,      // snap sendplc     br0 ff ff ff ff ff ff 11 22 33 44 55 66 aa 55 01 02 03 04 05 06
    NL60211_SEND_WIFI,     // snap sendwifi    br0 ff ff ff ff ff ff 11 22 33 44 55 66 aa 55 01 02 03 04 05 06
    NL60211_SEND_FLOOD,    // snap sendflood   br0 ff ff ff ff ff ff 11 22 33 44 55 66 aa 55 01 02 03 04 05 06
    NL60211_SEND_BEST,     // snap sendbest    br0 ff ff ff ff ff ff 11 22 33 44 55 66 aa 55 01 02 03 04 05 06
    NL60211_GETSA,         // snap getsa       br0
};

// inside nl60211msg.buf
// response
struct nl60211_debug_res {
    int32_t     return_code;
    uint32_t    len;
    char        buf[];
};
struct nl60211_getmeshid_res {
    int32_t     return_code;
    uint32_t    id_len;
    char        id[];
};
struct nl60211_setmeshid_res {
    int32_t     return_code;
};
struct nl60211_recv_res {
    int32_t     return_code;
    uint32_t    recv_len;
    uint8_t     recv_buf[];
};
struct nl60211_recvonce_res {
    int32_t     return_code;
    uint32_t    recv_len;
    uint8_t     recv_buf[];
};
struct nl60211_recvcancel_res {
    int32_t     return_code;
};
struct nl60211_sendplc_res {
    int32_t     return_code;
};
struct nl60211_sendwifi_res {
    int32_t     return_code;
};
struct nl60211_sendflood_res {
    int32_t     return_code;
};
struct nl60211_sendbest_res {
    int32_t     return_code;
};
struct nl60211_getsa_res {
    int32_t     return_code;
    uint32_t    sa_len;
    uint8_t     sa[];
};
// request
struct nl60211_debug_req {
    uint32_t    len;
    uint8_t     buf[];
};
struct nl60211_getmeshid_req {
};
struct nl60211_setmeshid_req {
    uint32_t    id_len;
    char        id[];
};
struct nl60211_recv_req {
    uint8_t     ether_type[2];
};
struct nl60211_recvonce_req {
    uint8_t     ether_type[2];
};
struct nl60211_recvcancel_req {
};
struct nl60211_sendplc_req {
    uint32_t    total_len;
    uint8_t     da[6];
    uint8_t     sa[6];
    uint8_t     ether_type[2];
    uint8_t     payload[];
};
struct nl60211_sendwifi_req {
    uint32_t    total_len;
    uint8_t     da[6];
    uint8_t     sa[6];
    uint8_t     ether_type[2];
    uint8_t     payload[];
};
struct nl60211_sendflood_req {
    uint32_t    total_len;
    uint8_t     da[6];
    uint8_t     sa[6];
    uint8_t     ether_type[2];
    uint8_t     payload[];
};
struct nl60211_sendbest_req {
    uint32_t    total_len;
    uint8_t     da[6];
    uint8_t     sa[6];
    uint8_t     ether_type[2];
    uint8_t     payload[];
};
struct nl60211_getsa_req {
};
#define MAX_PAYLOAD 2048 /* maximum payload size for request&response */
// This buffer is for tx & "rx". And it contains socket message header:"struct msghdr" for simplifying.
struct nl60211msg {
    struct nlmsghdr     nl_msghdr;
    // netlink payload start
    unsigned int        if_index;
    char                buf[MAX_PAYLOAD];
    // netlink payload end
};

#if IN_JETSON
struct net_bridge_hmc *snap;
#endif
void test_hmc_gen_pkt_snap(unsigned int total_len, unsigned char *raw, uint32_t type)
{
#if IN_JETSON
    unsigned int i = 0;
    unsigned int proto = 0xAA55;
    struct sk_buff *new_sk;
    struct ethhdr *ether;
    //const u8 da[ETH_ALEN] = {0x00,0x04,0x4b,0xe6,0xec,0x3d};
    //const u8 da[ETH_ALEN] = {0x00,0x19,0x94,0x38,0xfd,0x8e};
    //const u8 sa[ETH_ALEN] = {0x00,0x04,0x4b,0xec,0x28,0x3b};
    u8 da[ETH_ALEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    u8 sa[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    u8 *pos;

    for (i=0; i<total_len; i++) {
        if (i<6) {
            da[i]=raw[i];
        } else if (i<12) {
            sa[i-6]=raw[i];
        } else if (i==12) {
            proto = proto & 0x00FF;
            proto = proto | (((unsigned int)raw[i])<<8);
        } else if (i==13) {
            proto = proto & 0xFF00;
            proto = proto | (((unsigned int)raw[i])<<0);
            i=14;
            break;
        }
    }

    //TRACE();

    if (total_len > 19) {
        new_sk = dev_alloc_skb(2 + total_len + 2);
    } else {
        new_sk = dev_alloc_skb(128);
    }

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
        pos = skb_put(new_sk, total_len-14);
        for (i=i; i<total_len; i++) {
            *pos++ = raw[i];
        }
    }

    skb_reset_mac_header(new_sk);

    br_hmc_print_skb(new_sk, "test_hmc_gen_pkt_snap", 0);

    switch (type) {
        case NL60211_SEND_PLC:
            snap->egress = HMC_PORT_PLC;
            break;
        case NL60211_SEND_WIFI:
            snap->egress = HMC_PORT_WIFI;
            break;
        case NL60211_SEND_FLOOD:
            snap->egress = HMC_PORT_FLOOD;
            break;
        case NL60211_SEND_BEST:
            snap->egress = HMC_PORT_FLOOD;
            break;
    }

    br_hmc_forward(new_sk, snap);
#endif
}

static struct sock *nl_sk = NULL;
static int pr_debug_en = 1;
static int pid_of_sender;
static int pid_of_reciever;
static unsigned int if_index;
static unsigned int command_type;
static unsigned int is_nl60211_in_recv = 0;
static unsigned int is_nl60211_in_recv_once = 0;
static unsigned char recv_ether_type[2];

static void nl60211_cmd_simple_response(struct nl60211msg *nlreq, uint32_t payload_len, void *payload)
{
    //response
    struct sk_buff *skbres;
    struct nl60211msg *nlres;
    uint32_t nlmsgsize;
    int ret;

    if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
        return;
    nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) + payload_len;
    skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);
    if(!skbres) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    nlres = (struct nl60211msg *)nlmsg_put(skbres,0,0,NLMSG_DONE,nlmsgsize,0);
    NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */
    //copy input command to response
    nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
    nlres->if_index = nlreq->if_index;
    memcpy(nlres->buf, payload, payload_len);
    //nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
    ret = nlmsg_unicast(nl_sk, skbres, pid_of_sender);
    if(ret<0)
        printk(KERN_INFO "Error while sending back to user\n");
    return;
}

static void nl60211_cmd_debug_dump(struct nl60211msg *nlreq)
{
    pr_warn("====== SNAP DUMP ======\n");
    pr_warn("pr_debug_en = %d\n", pr_debug_en);
    pr_warn("pid_of_sender = %d\n", pid_of_sender);
    pr_warn("pid_of_reciever = %d\n", pid_of_reciever);
    pr_warn("if_index = %u\n", if_index);
    pr_warn("command_type = 0x%04X\n", command_type);
    pr_warn("is_nl60211_in_recv = %u\n", is_nl60211_in_recv);
    pr_warn("is_nl60211_in_recv_once = %u\n", is_nl60211_in_recv_once);
    pr_warn("recv_ether_type[0] = %u\n", recv_ether_type[0]);
    pr_warn("recv_ether_type[1] = %u\n", recv_ether_type[1]);
}

static void nl60211_cmd_debug(struct nl60211msg *nlreq)
{
enum {
    SET_DEBUG_PRINT=0,
};
    //request
    struct nl60211_debug_req *req = (struct nl60211_debug_req *)nlreq->buf;
    //response
    //struct sk_buff *skbres;
    //struct nl60211msg *nlres;
    //struct nl60211_debug_res *res;
    struct nl60211_debug_res simpleres;
    //uint32_t nlmsgsize;
    int32_t return_code = 0;
    //int ret;
    //local

    //request
    do {
        if (req->len == 0)
        {
            simpleres.return_code = return_code;
            simpleres.len = 0;
            nl60211_cmd_debug_dump(nlreq);

            //response
            nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
            return;
        }
        else
        {
            simpleres.return_code = return_code;
            simpleres.len = 0;
            switch (req->buf[0]) {
                case SET_DEBUG_PRINT:
                    if (req->len >= 2) {
                        pr_debug_en = req->buf[1];
                        nl60211_cmd_debug_dump(nlreq);
                        nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
                        return;
                    }
                    break;
            }
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
    uint32_t nlmsgsize;
    int32_t return_code = 0;
    int ret;
    //local
    //temp
    char id[]="mymesh222";
    unsigned int id_len = strlen(id);

    //response
    if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
        return;
    nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) + sizeof(struct nl60211_getmeshid_res) + id_len + 1/* char: \'0 */;
    skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);

    if(!skbres) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlres = (struct nl60211msg *)nlmsg_put(skbres,0,0,NLMSG_DONE,nlmsgsize,0);
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
    ret = nlmsg_unicast(nl_sk, skbres, pid_of_sender);

    if(ret<0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static void nl60211_cmd_setmeshid(struct nl60211msg *nlreq)
{
    //request
    struct nl60211_setmeshid_req *req = (struct nl60211_setmeshid_req *)nlreq->buf;
    //response
    //struct sk_buff *skbres;
    //struct nl60211msg *nlres;
    //struct nl60211_setmeshid_res *res;
    //uint32_t nlmsgsize;
    struct nl60211_setmeshid_res simpleres;
    int32_t return_code = 0;
    //int ret;
    //local

    //request
    return_code = -100; // set mesh id is TBD
    printk(KERN_ERR "id_len = %u\n", req->id_len);
    if (req->id_len) {
        printk(KERN_ERR "setmeshid : %s\n", req->id);
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
    pid_of_reciever = pid_of_sender;

    pr_info("%s() start ...\n", __func__);

    //response
    //simpleres.return_code = 0;
    //nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_recv_once(struct nl60211msg *nlreq)
{
    //request
    struct nl60211_recvonce_req *req = (struct nl60211_recvonce_req *)nlreq->buf;
    //response
    //struct nl60211_recvonce_res simpleres;

    recv_ether_type[0] = req->ether_type[0];
    recv_ether_type[1] = req->ether_type[1];
    is_nl60211_in_recv_once = 1;
    pid_of_reciever = pid_of_sender;

    pr_info("%s() start ...\n", __func__);

    //response
    //simpleres.return_code = 0;
    //nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
}

static void nl60211_cmd_recv_cancel(struct nl60211msg *nlreq)
{
    //request
    //struct nl60211_recvcancel_req *req_payload = (struct nl60211_recv_req *)snap_req->buf;
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
    struct nl60211_sendplc_req *req = (struct nl60211_sendplc_req *)nlreq->buf;
    unsigned char *req_rawdata = req->da;

    if (pr_debug_en) {
        for(i=0; i<req->total_len; i++) {
            pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i, (unsigned int)req_rawdata[i], (unsigned int)req_rawdata[i]);
        }
    }

    test_hmc_gen_pkt_snap(req->total_len, req_rawdata, nlreq->nl_msghdr.nlmsg_type&0x00FF);

    //response
    {
        struct nl60211_sendplc_res simpleres;
        simpleres.return_code = 0;
        nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
    }
}

static void nl60211_cmd_sendwifi(struct nl60211msg *nlreq)
{
    unsigned int i;
    struct nl60211_sendwifi_req *req = (struct nl60211_sendwifi_req *)nlreq->buf;
    unsigned char *req_rawdata = req->da;

    if (pr_debug_en) {
        for(i=0; i<req->total_len; i++) {
            pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i, (unsigned int)req_rawdata[i], (unsigned int)req_rawdata[i]);
        }
    }

    test_hmc_gen_pkt_snap(req->total_len, req_rawdata, nlreq->nl_msghdr.nlmsg_type&0x00FF);

    //response
    {
        struct nl60211_sendwifi_res simpleres;
        simpleres.return_code = 0;
        nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
    }
}

static void nl60211_cmd_sendflood(struct nl60211msg *nlreq)
{
    unsigned int i;
    struct nl60211_sendflood_req *req = (struct nl60211_sendflood_req *)nlreq->buf;
    unsigned char *req_rawdata = req->da;

    if (pr_debug_en) {
        for(i=0; i<req->total_len; i++) {
            pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i, (unsigned int)req_rawdata[i], (unsigned int)req_rawdata[i]);
        }
    }

    test_hmc_gen_pkt_snap(req->total_len, req_rawdata, nlreq->nl_msghdr.nlmsg_type&0x00FF);

    //response
    {
        struct nl60211_sendflood_res simpleres;
        simpleres.return_code = 0;
        nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
    }
}

static void nl60211_cmd_sendbest(struct nl60211msg *nlreq)
{
    unsigned int i;
    struct nl60211_sendbest_req *req = (struct nl60211_sendbest_req *)nlreq->buf;
    unsigned char *req_rawdata = req->da;

    if (pr_debug_en) {
        for(i=0; i<req->total_len; i++) {
            pr_warn("req_payload_raw[%d] = %3d (0x%02X)\n", i, (unsigned int)req_rawdata[i], (unsigned int)req_rawdata[i]);
        }
    }

    test_hmc_gen_pkt_snap(req->total_len, req_rawdata, nlreq->nl_msghdr.nlmsg_type&0x00FF);

    //response
    {
        struct nl60211_sendbest_res simpleres;
        simpleres.return_code = 0;
        nl60211_cmd_simple_response(nlreq, sizeof(simpleres), &simpleres);
    }
}

static void nl60211_cmd_getsa(struct nl60211msg *nlreq)
{
    //request
    //response
    struct sk_buff *skbres;
    struct nl60211msg *nlres;
    struct nl60211_getsa_res *res;
    uint32_t nlmsgsize;
    int32_t return_code = 0;
    int ret;
    //local
    //temp

    //response
    if (nlreq->nl_msghdr.nlmsg_type & NL60211FLAG_NO_RESPONSE)
        return;
    nlmsgsize = sizeof(struct nl60211msg) - sizeof(nlres->buf) + sizeof(struct nl60211_getsa_res) + 6;
    skbres = nlmsg_new(nlmsgsize, GFP_ATOMIC);

    if(!skbres) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlres = (struct nl60211msg *)nlmsg_put(skbres,0,0,NLMSG_DONE,nlmsgsize,0);
    NETLINK_CB(skbres).dst_group = 0; /* not in mcast group */

    //copy input command to response
    nlres->nl_msghdr.nlmsg_type = nlreq->nl_msghdr.nlmsg_type;
    nlres->if_index = nlreq->if_index;

    res = (struct nl60211_getsa_res *)nlres->buf;
    res->return_code = return_code;
    res->sa_len = 6;
    memcpy(res->sa, snap->br_addr, 6);

    //nlmsg_end(skb_res, (struct nlmsghdr *)snap_res);
    ret = nlmsg_unicast(nl_sk, skbres, pid_of_sender);

    if(ret<0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int nl60211_rx_callback_proto_filter(size_t len, u8 *data)
{
    struct sk_buff *skb_res;
    struct nl60211msg *snap_res;
    unsigned int msg_size;
    struct nl60211_recv_res *res_payload;
    int ret;

    msg_size = sizeof(struct nl60211msg) - sizeof(snap_res->buf) + sizeof(struct nl60211_recv_res) + len;

    skb_res = nlmsg_new(msg_size, GFP_ATOMIC);
    if(!skb_res) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        is_nl60211_in_recv = 0;
        is_nl60211_in_recv_once = 0;
        return -1;
    }

    snap_res = (struct nl60211msg *)nlmsg_put(skb_res,0,0,NLMSG_DONE,msg_size,0);
    NETLINK_CB(skb_res).dst_group = 0; /* not in mcast group */

    //copy input command to response
    snap_res->nl_msghdr.nlmsg_type = command_type;
    snap_res->if_index = if_index;

    res_payload = (struct nl60211_recv_res *)snap_res->buf;
    res_payload->return_code = 113;
    res_payload->recv_len = len;
    memcpy(res_payload->recv_buf, data, len);

    ret = nlmsg_unicast(nl_sk, skb_res, pid_of_reciever);

    if(ret<0)
        printk(KERN_INFO "Error while sending back to user\n");

    return 0;
}

int nl60211_rx_callback(struct sk_buff *skb)
{
    size_t len ,i;
    u8 *data; 

    data = (u8 *) skb_mac_header(skb);
   //data = (u8 *) skb->head;

    if (skb_is_nonlinear(skb)) {
            len = skb->data_len;
    } else {
            len = skb->len;
    }

    if (is_nl60211_in_recv == 0 && is_nl60211_in_recv_once == 0) {
        return 0;
    }

    do {
        if (len < 14)
            break;
        if (data[12] != recv_ether_type[0])
            break;
        if (data[13] != recv_ether_type[1])
            break;
        //match
        is_nl60211_in_recv_once = 0;
        pr_info("[SNAP RX] ether_type = %02X %02X, len = %ld\n", data[12], data[13], len);
        for(i=14; i<len; i++) {
            pr_info("[SNAP RX] 0x%02X\n", data[i]);
            if (i>=17)
                break;
        }
        nl60211_rx_callback_proto_filter(len+skb->mac_len, data);
        return 0;
    } while (0);

    return 0;
}

static void nl60211_netlink_input(struct sk_buff *skb_in)
{
    struct nl60211msg *nlreq;
    struct nlmsghdr *nlh;

    printk(KERN_INFO "\nEntering: %s\n", __FUNCTION__);

    // parsing request
    nlh = (struct nlmsghdr*)skb_in->data;
    nlreq = (struct nl60211msg *)skb_in->data;

    //printk(KERN_INFO "Netlink received msg payload:%s\n", (char*)nlmsg_data(nlh));
    printk(KERN_INFO "skb_in: len=%d, data_len=%d, mac_len=%d\n", skb_in->len, skb_in->data_len, skb_in->mac_len);
    printk(KERN_INFO "skb_in          = %p\n", skb_in);
    printk(KERN_INFO "skb_in->data    = %p\n", skb_in->data);
    printk(KERN_INFO "nlh             = %p\n", nlh);
    printk(KERN_INFO "nlmsg_data(nlh) = %p\n", nlmsg_data(nlh));
    printk(KERN_INFO "nlh->nlmsg_len   = %d\n", nlh->nlmsg_len);
    printk(KERN_INFO "nlh->nlmsg_type  = %d\n", nlh->nlmsg_type);
    printk(KERN_INFO "nlh->nlmsg_flags = %d\n", nlh->nlmsg_flags);
    printk(KERN_INFO "nlh->nlmsg_seq   = %d\n", nlh->nlmsg_seq);
    printk(KERN_INFO "nlh->nlmsg_pid   = %d\n", nlh->nlmsg_pid);
    //printk(KERN_INFO "user_data[0]     = %d\n", snap_req->buf[0]);
    //printk(KERN_INFO "user_data[1]     = %d\n", snap_req->buf[1]);
    //printk(KERN_INFO "user_data[2]     = %d\n", snap_req->buf[2]);
    printk(KERN_INFO "if_index     = %d\n", nlreq->if_index);

    pid_of_sender = nlreq->nl_msghdr.nlmsg_pid;
    if_index = nlreq->if_index;
    command_type = nlreq->nl_msghdr.nlmsg_type;
    switch (nlh->nlmsg_type & 0x00FF)
    {
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
            nl60211_cmd_recv(nlreq);
            break;
        case NL60211_RECV_ONCE:
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
        default:
            pr_warn("[SNAP] Unknown command = %d\n", nlh->nlmsg_type);
    }
}

struct netlink_kernel_cfg nl60211_netlink_cfg = {
    .input = nl60211_netlink_input,
};

static int test_br_hmc_rx_snap(struct sk_buff *skb)
{
    pr_info("*** BR-HMC SNAP rx callback test (skb len=%d, data_len=%d)\n", skb->len, skb->data_len);
    //br_hmc_print_skb(skb, "test_br_hmc_rx_snap", 0);
    nl60211_rx_callback(skb);
    return 0;
}
static struct net_bridge_hmc_ops test_br_hmc_ops_f = {
    .rx = test_br_hmc_rx_snap,
};
int nl60211_netlink_init(void)
{
    printk("Entering: %s\n",__FUNCTION__);
    //This is for 3.6 kernels and above.

    nl_sk = netlink_kernel_create(&init_net, NETLINK_60211, &nl60211_netlink_cfg);
    //nl_sk = netlink_kernel_create(&init_net, NETLINK_60211, 0, hello_nl_recv_msg,NULL,THIS_MODULE);
    if(!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    snap = br_hmc_alloc("nl60211", &test_br_hmc_ops_f);

    return 0;
}

void nl60211_netlink_exit(void)
{
    printk(KERN_INFO "exiting snap module\n");
    if (nl_sk)
        netlink_kernel_release(nl_sk);
}

