
#include "everything.h"

#define STR_CTRL            "ctrl"
#define STR_GETMESHID       "getmeshid"
#define STR_SETMESHID       "setmeshid"
#define STR_RECV            "recv"
#define STR_RECV_ONCE       "recvonce"
#define STR_RECV_CANCEL     "recvcancel"
#define STR_PLCSEND         "sendplc"
#define STR_WIFISEND        "sendwifi"
#define STR_FLOODSEND       "sendflood"
#define STR_BESTSEND        "sendbest"
#define STR_GETSA           "getsa"
#define STR_ADDMPATH        "addmpath"
#define STR_DELMPATH        "delmpath"
#define STR_SETMPATH        "setmpath"
#define STR_GETMPATH        "getmpath"
#define STR_DUMPMPATH       "dumpmpath"
#define STR_PLCGETMETRIC    "plcgetmetric"
#define STR_PLCSETMETRIC    "plcsetmetric"
#define STR_PLCGETMPARA     "plcgetmpara"
#define STR_PLCSETMPARA     "plcsetmpara"
#define STR_PLCDUMPSTA      "plcdumpsta"
#define STR_PLCDUMPMPATH    "plcdumpmpath"

struct sockaddr_nl src_addr, dest_addr;
//struct nlmsghdr *nlh = NULL;
//struct iovec iov;
int sock_fd;
struct nl60211skmsg sk_msg_send;
struct nl60211skmsg sk_msg_recv;

int if_nl_init(void)
{
	sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_60211);
	if (sock_fd < 0)
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */

	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */
	return 0;
}

int if_nl_deinit(void)
{
	close(sock_fd);
	return 0;
}

int if_nl_send(uint16_t type, unsigned int if_index, uint32_t buf_len)
{
	struct nl60211msg *msg = &(sk_msg_send.nl_msg);

	if (buf_len > MAX_PAYLOAD)
		return -1;

	msg->nl_msghdr.nlmsg_len =
		sizeof(struct nl60211msg) - MAX_PAYLOAD + buf_len;

	msg->nl_msghdr.nlmsg_pid = getpid();
	//printf("if_nl_send() : msg->nl_msghdr.nlmsg_pid = %d\n", msg->nl_msghdr.nlmsg_pid);
	msg->nl_msghdr.nlmsg_flags = 0;
	msg->nl_msghdr.nlmsg_type = type;

	msg->if_index = if_index;

	// 2. add netlink message to iov
	sk_msg_send.iov.iov_base = (void *)msg;
	sk_msg_send.iov.iov_len = msg->nl_msghdr.nlmsg_len;

	// 3. combine iov to socket message iov
	sk_msg_send.sk_msghdr.msg_iov = &(sk_msg_send.iov);
	sk_msg_send.sk_msghdr.msg_iovlen = 1;

	// 4. set destination address
	sk_msg_send.sk_msghdr.msg_name = (void *)&dest_addr;
	sk_msg_send.sk_msghdr.msg_namelen = sizeof(dest_addr);

	//ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
	sendmsg(sock_fd, &(sk_msg_send.sk_msghdr), 0);
	return 0;
}

int if_nl_recv(void)
{
	struct nl60211msg *msg = &(sk_msg_recv.nl_msg);

	sk_msg_recv.iov.iov_base = (void *)msg;
	sk_msg_recv.iov.iov_len = sizeof(struct nl60211msg);

	sk_msg_recv.sk_msghdr.msg_iov = &(sk_msg_recv.iov);
	sk_msg_recv.sk_msghdr.msg_iovlen = 1;

	//ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
	recvmsg(sock_fd, &(sk_msg_recv.sk_msghdr), 0);
	return 0;
}

/* Returns false if 'prefix' is a not empty prefix of 'string'.
 */
bool matches(const char *prefix, const char *string)
{
	if (!*prefix)
		return true;
	while (*string && *prefix == *string) {
		prefix++;
		string++;
	}

	return !!*prefix;
}

static unsigned int nametoindex(const char *name)
{
	unsigned int if_idx = (uint32_t)if_nametoindex(name);

	if (if_idx == 0) {
		fprintf(stderr, "Interface \"%s\" is unknown\n", name);
		exit(-1);
	}
	return if_idx;
}

int do_ctrl(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_ctrl_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_ctrl_res *res;

	printf("ctrl proc start ... if = %s, idx = %d\n", argv[0], if_idx);
	if (argc <= 1) {
		printf("no control code, exit!\n");
		exit(-1);
	}
	req = (struct nl60211_ctrl_req *)sk_msg_send.nl_msg.buf;
	req->ctrl_code = scan_u32(argv[1]);

	switch(req->ctrl_code)
	{
		case NL60211_CTRL_GET_VERSION:
			break;
		case NL60211_CTRL_DUMP_KERNEL_MSG:
			break;
		case NL60211_CTRL_GET_DEBUG_PRINT:
			break;
		case NL60211_CTRL_SET_DEBUG_PRINT:
			if (argc <= 2) {
				printf("no argumnet, exit!\n");
				exit(-1);
			}
			req->u.debugPrint = scan_u8(argv[2]);
			break;
		case NL60211_CTRL_GET_RECV_PORT_DETECT:
			break;
		case NL60211_CTRL_SET_RECV_PORT_DETECT:
			if (argc <= 2) {
				printf("no argumnet, exit!\n");
				exit(-1);
			}
			req->u.recvPortDetect = scan_u8(argv[2]);
			break;
		case NL60211_CTRL_SELF_TEST_001:
		case NL60211_CTRL_SELF_TEST_002:
		case NL60211_CTRL_SELF_TEST_003:
		case NL60211_CTRL_SELF_TEST_004:
			self_test_proc(req->ctrl_code, if_idx);
			return 0;
		default:
			printf("Error: unknown control code!\n");
			exit(-1);
	}

	if_nl_send(NL60211_CTRL, if_idx, sizeof(struct nl60211_ctrl_req));
	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_ctrl_res *)nlres->buf;
	printf("%-15s = %d\n", "nlmsg_type", nlres->nl_msghdr.nlmsg_type);
	printf("%-15s = %d\n", "if_index", nlres->if_index);
	printf("%-15s = %d\n", "return_code", res->return_code);
	switch(res->ctrl_code)
	{
		case NL60211_CTRL_GET_VERSION:
			printf("%-15s = 0x%08X\n", "verNum", res->u.verNum);
			printf("%-15s = 0x%04X\n", "data_struct ver", res->u.verNum >> 16);
			printf("%-15s = 0x%04X\n", "sub ver", res->u.verNum & 0xFFFF);
			break;
		case NL60211_CTRL_DUMP_KERNEL_MSG:
			break;
		case NL60211_CTRL_GET_DEBUG_PRINT:
			printf("%-15s = %d\n", "debugPrint", res->u.debugPrint);
			break;
		case NL60211_CTRL_SET_DEBUG_PRINT:
			break;
		case NL60211_CTRL_GET_RECV_PORT_DETECT:
			printf("%-15s = %d\n", "recvPortDetect", res->u.recvPortDetect);
			break;
		case NL60211_CTRL_SET_RECV_PORT_DETECT:
			break;
		case NL60211_CTRL_SELF_TEST_001:
			return 0;
		case NL60211_CTRL_SELF_TEST_002:
			return 0;
		case NL60211_CTRL_SELF_TEST_003:
			return 0;
		case NL60211_CTRL_SELF_TEST_004:
			return 0;
		default:
			printf("Error: unknown control code!\n");
			exit(-1);
	}

	return 0;
}

int do_getmeshid(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	//response
	struct nl60211msg *nlres;
	struct nl60211_getmeshid_res *res;

	printf("get mesh id of :%s, idx = %d\n", argv[0], if_idx);

	if_nl_send(NL60211_GETMESHID, if_idx, 0);
	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_getmeshid_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	printf("id_len      = %d\n", res->id_len);
	printf("id          = %s\n", res->id);

	return 0;
}

int do_setmeshid(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_setmeshid_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_setmeshid_res *res;

	if (argc) {
		printf("set mesh id of :%s, idx = %d, id = %s\n",
		       argv[0], if_idx, argv[1]);
	}
	req = (struct nl60211_setmeshid_req *)sk_msg_send.nl_msg.buf;
	req->id_len = strlen(argv[1]);
	if (req->id_len > 32)
		printf("Error: mesh id must less or equal than 32\n");

	memcpy(req->id, argv[1], req->id_len);
	req->id[req->id_len] = 0; // '\0' for the end of C string
	printf("req->id_len = %d\n", req->id_len);
	printf("req->id = %s\n", req->id);
	if_nl_send(
		NL60211_SETMESHID,
		if_idx,
		sizeof(struct nl60211_setmeshid_req) +
			req->id_len +
			1/* '\0' for teh end of C string */);

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_setmeshid_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);

	return 0;
}

int do_recv(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_recv_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_recv_res *res;
	unsigned int i;

	printf("do_recv, idx = %d\n", if_idx);
	argc--;
	argv++;
	if (argc != 2) {
		printf("ether_type must be 2 bytes!\n");
		return -1;
	}
	req = (struct nl60211_recv_req *)sk_msg_send.nl_msg.buf;
	req->ether_type[0] = scan_x8(argv[0]);
	req->ether_type[1] = scan_x8(argv[1]);
	if_nl_send(NL60211_RECV, if_idx, sizeof(struct nl60211_recv_req));

	do {
		printf("start recv ......\n");
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
		res = (struct nl60211_recv_res *)nlres->buf;
		printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
		printf("if_index    = %d\n", nlres->if_index);
		printf("return_code = %d\n", res->return_code);
		printf("recv_len    = %d\n", res->recv_len);
		for (i = 0; i < res->recv_len; i++) {
			printf("%02X ", res->recv_buf[i]);
			if ((i % 16) == 15)
				printf("\n");
		}
		printf("\n");
	} while (1);

	return 0;
}

int do_recvonce(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_recv_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_recv_res *res;
	unsigned int i;

	printf("do_recv, idx = %d\n", if_idx);
	argc--;
	argv++;
	if (argc != 2) {
		printf("ether_type must be 2 bytes!\n");
		return -1;
	}
	req = (struct nl60211_recv_req *)sk_msg_send.nl_msg.buf;
	req->ether_type[0] = scan_x8(argv[0]);
	req->ether_type[1] = scan_x8(argv[1]);
	if_nl_send(NL60211_RECV_ONCE, if_idx, sizeof(struct nl60211_recv_req));

	do {
		printf("start recv ......\n");
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
		res = (struct nl60211_recv_res *)nlres->buf;
		printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
		printf("if_index    = %d\n", nlres->if_index);
		printf("return_code = %d\n", res->return_code);
		printf("recv_len    = %d\n", res->recv_len);
		for (i = 0; i < res->recv_len; i++) {
			printf("%02X ", res->recv_buf[i]);
			if ((i % 16) == 15)
				printf("\n");
		}
		printf("\n");
	} while (0);

	return 0;
}
int do_recvcancel(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	//response
	struct nl60211msg *nlres;
	struct nl60211_getmeshid_res *res;

	if_nl_send(NL60211_RECV_CANCEL, if_idx, 0);
	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_getmeshid_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);

	return 0;
}

int do_sendplc(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_sendplc_req *req;
	uint8_t *req_raw;
	//response
	struct nl60211msg *nlres;
	struct nl60211_sendplc_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;

	req = (struct nl60211_sendplc_req *)sk_msg_send.nl_msg.buf;
	req->total_len = argc;
	req_raw = req->da; //first
	for (i = 0; i < argc; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req_raw[i] = (uint8_t)temp;
	}

	if_nl_send(NL60211_SEND_PLC,
		if_idx,
		sizeof(req->total_len) +/*da,sa,ether_type,payload*/argc);

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_sendplc_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);

	return 0;
}
int do_sendwifi(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_sendwifi_req *req;
	uint8_t *req_raw;
	//response
	struct nl60211msg *nlres;
	struct nl60211_sendwifi_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;

	req = (struct nl60211_sendwifi_req *)sk_msg_send.nl_msg.buf;
	req->total_len = argc;
	req_raw = req->da; //first
	for (i = 0; i < argc; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req_raw[i] = (uint8_t)temp;
	}

	if_nl_send(NL60211_SEND_WIFI,
		if_idx,
		sizeof(req->total_len) +/*da,sa,ether_type,payload*/argc);

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_sendwifi_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);

	return 0;
}

int do_sendflood(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_sendflood_req *req;
	uint8_t *req_raw;
	//response
	struct nl60211msg *nlres;
	struct nl60211_sendflood_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;

	req = (struct nl60211_sendflood_req *)sk_msg_send.nl_msg.buf;
	req->total_len = argc;
	req_raw = req->da; //first
	for (i = 0; i < argc; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req_raw[i] = (uint8_t)temp;
	}

	if_nl_send(
		NL60211_SEND_FLOOD,
		if_idx,
		sizeof(req->total_len) +/*da,sa,ether_type,payload*/argc);

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_sendflood_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);

	return 0;
}

int do_sendbest(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_sendbest_req *req;
	uint8_t *req_raw;
	//response
	struct nl60211msg *nlres;
	struct nl60211_sendbest_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;

	req = (struct nl60211_sendbest_req *)sk_msg_send.nl_msg.buf;
	req->total_len = argc;
	req_raw = req->da; //first
	for (i = 0; i < argc; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req_raw[i] = (uint8_t)temp;
	}

	if_nl_send(
		NL60211_SEND_BEST,
		if_idx,
		sizeof(req->total_len) +/*da,sa,ether_type,payload*/argc);

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_sendbest_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);

	return 0;
}

int do_getsa(int argc, char **argv)
{
	uint32_t i;
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	//response
	struct nl60211msg *nlres;
	struct nl60211_getsa_res *res;

	printf("get sa of :%s, idx = %d\n", argv[0], if_idx);

	if_nl_send(NL60211_GETSA, if_idx, 0);
	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_getsa_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	printf("sa_len      = %d\n", res->sa_len);
	printf("sa          =\n");
	for (i = 0; i < res->sa_len; i++)
		printf("%02X ", res->sa[i]);

	printf("\n");

	return 0;
}

int do_addmpath(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_addmpath_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_addmpath_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != ETH_ALEN+1)
		printf("Error: Must input %d bytes da!\n", ETH_ALEN+1);

	req = (struct nl60211_addmpath_req *)sk_msg_send.nl_msg.buf;
	for (i = 0; i < ETH_ALEN; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req->da[i] = (uint8_t)temp;
	}
	req->iface_id = scan_u16(argv[i]);

	if_nl_send(
		NL60211_ADD_MPATH,
		if_idx,
		sizeof(struct nl60211_addmpath_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_addmpath_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	return 0;
}

int do_delmpath(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_delmpath_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_delmpath_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != ETH_ALEN+1)
		printf("Error: Must input %d bytes da!", ETH_ALEN+1);

	req = (struct nl60211_delmpath_req *)sk_msg_send.nl_msg.buf;
	for (i = 0; i < ETH_ALEN; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req->da[i] = (uint8_t)temp;
	}
	req->iface_id = scan_u16(argv[i]);

	if_nl_send(
		NL60211_DEL_MPATH,
		if_idx,
		sizeof(struct nl60211_delmpath_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_delmpath_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	return 0;
}

int do_setmpath(int argc, char **argv)
{
	return 0;
}

int do_getmpath(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_getmpath_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_getmpath_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != ETH_ALEN+1)
		printf("Error: Must input %d bytes da!", ETH_ALEN+1);

	req = (struct nl60211_getmpath_req *)sk_msg_send.nl_msg.buf;
	for (i = 0; i < ETH_ALEN; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req->da[i] = (uint8_t)temp;
	}
	req->iface_id = scan_u16(argv[i]);

	if_nl_send(
		NL60211_GET_MPATH,
		if_idx,
		sizeof(struct nl60211_getmpath_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_getmpath_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	if (res->return_code == 0) {
		printf("%-21s %-10s %-10s %-10s %-10s\n",
		       "DA", "SN", "METRIC", "FLAG", "IFACE_ID");
		printf("%02X:%02X:%02X:%02X:%02X:%02X     ",
		       res->da[0], res->da[1], res->da[2],
		       res->da[3], res->da[4], res->da[5]);
		printf("%-10d %-10d %-10d %-10d\n",
		       res->sn, res->metric, res->flags, res->iface_id);
	}
	return 0;
}

int do_dumpmpath(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request

	//response
	struct nl60211msg *nlres;
	struct nl60211_getmpath_res *res;
	//int i, temp;

	if_nl_send(NL60211_DUMP_MPATH, if_idx, 0);
	printf("%-21s %-10s %-10s %-10s %-10s\n",
	       "DA", "SN", "METRIC", "FLAG", "IFACE_ID");

	while (1) {
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
		res = (struct nl60211_getmpath_res *)nlres->buf;
		if (res->return_code < 0)
			break;
		//printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
		//printf("if_index    = %d\n", nlres->if_index);
		//printf("return_code = %d\n", res->return_code);
		printf("%02X:%02X:%02X:%02X:%02X:%02X     ",
		       res->da[0], res->da[1], res->da[2],
		       res->da[3], res->da[4], res->da[5]);
		printf("%-10u %-10u %-10u %-10u\n",
		       res->sn, res->metric, res->flags, res->iface_id);
	}
	return 0;
}

int do_plcgetmetric(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_plcgetmetric_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_plcgetmetric_res *res;
	int i, temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != ETH_ALEN)
		printf("Error: Must input %d bytes da!", ETH_ALEN);

	req = (struct nl60211_plcgetmetric_req *)sk_msg_send.nl_msg.buf;
	for (i = 0; i < ETH_ALEN; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req->da[i] = (uint8_t)temp;
	}

	if_nl_send(
		NL60211_PLC_GET_METRIC,
		if_idx,
		sizeof(struct nl60211_plcgetmetric_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_plcgetmetric_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	printf("metric      = %d\n", res->metric);
	return 0;
}

int do_plcsetmetric(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_plcsetmetric_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_plcsetmetric_res *res;
	int i;
	u32 temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != ETH_ALEN + 1)
		printf("Error: Must input %d bytes da! and 1 byte metric",
			ETH_ALEN);

	req = (struct nl60211_plcsetmetric_req *)sk_msg_send.nl_msg.buf;
	for (i = 0; i < ETH_ALEN; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req->da[i] = (uint8_t)temp;
	}
	req->metric = scan_u32(argv[i]);

	if_nl_send(
		NL60211_PLC_SET_METRIC,
		if_idx,
		sizeof(struct nl60211_plcsetmetric_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_plcsetmetric_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	return 0;
}

int do_plcgetmpara(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_plcgetmpara_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_plcgetmpara_res *res;
	u32 temp;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != 1) {
		printf("Error: argument num error!\n");
		exit(-1);
	}

	if (sscanf(argv[0], "0x%x", &temp) == 0) {
		printf("Error: not a hexidecimal string!\n");
		exit(-1);
	}
	req = (struct nl60211_plcgetmpara_req *)sk_msg_send.nl_msg.buf;
	req->param_flags = temp;

	if_nl_send(
		NL60211_PLC_GET_MPARA,
		if_idx,
		sizeof(struct nl60211_plcgetmpara_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_plcgetmpara_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	printf("param_flags = %d\n", res->param_flags);
	if (res->return_code == 0) {
		printf("%-35s = %d\n", "MeshRetryTimeout",
			res->cfg.MeshRetryTimeout);
		printf("%-35s = %d\n", "MeshConfirmTimeout",
			res->cfg.MeshConfirmTimeout);
		printf("%-35s = %d\n", "MeshHoldingTimeout",
			res->cfg.MeshHoldingTimeout);
		printf("%-35s = %d\n", "MeshMaxPeerLinks",
			res->cfg.MeshMaxPeerLinks);
		printf("%-35s = %d\n", "MeshMaxRetries",
			res->cfg.MeshMaxRetries);
		printf("%-35s = %d\n", "MeshTTL",
			res->cfg.MeshTTL);
		printf("%-35s = %d\n", "element_ttl",
			res->cfg.element_ttl);
		printf("%-35s = %d\n", "MeshHWMPmaxPREQretries",
			res->cfg.MeshHWMPmaxPREQretries);
		printf("%-35s = %d\n", "path_refresh_time",
			res->cfg.path_refresh_time);
		printf("%-35s = %d\n", "min_discovery_timeout",
			res->cfg.min_discovery_timeout);
		printf("%-35s = %d\n", "MeshHWMPactivePathTimeout",
			res->cfg.MeshHWMPactivePathTimeout);
		printf("%-35s = %d\n", "MeshHWMPpreqMinInterval",
			res->cfg.MeshHWMPpreqMinInterval);
		printf("%-35s = %d\n", "MeshHWMPperrMinInterval",
			res->cfg.MeshHWMPperrMinInterval);
		printf("%-35s = %d\n", "MeshHWMPnetDiameterTraversalTime",
			res->cfg.MeshHWMPnetDiameterTraversalTime);
		printf("%-35s = %d\n", "rssi_threshold",
			res->cfg.rssi_threshold);
		printf("%-35s = %d\n", "plink_timeout",
			res->cfg.plink_timeout);
		printf("%-35s = %d\n", "beacon_interval",
			res->cfg.beacon_interval);
	}
	return 0;
}

int do_plcsetmpara(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_plcsetmpara_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_plcsetmpara_res *res;
	u32 temp;
	s32 value_for_set;
	u32 mask = 0x00000001;

	printf("argc = %d, if_idx = %d\n", argc, if_idx);
	argc--;
	argv++;
	if (argc != 2) {
		printf("Error: argument num error!\n");
		exit(-1);
	}

	req = (struct nl60211_plcsetmpara_req *)sk_msg_send.nl_msg.buf;
	if (sscanf(argv[0], "0x%x", &temp) == 0) {
		printf("Error: not a hexidecimal string!\n");
		exit(-1);
	}
	req->param_flags = temp;
	if (sscanf(argv[1], "%d", &value_for_set) == 0) {
		printf("Error: not a decimal string!\n");
		exit(-1);
	}
	memset(&req->cfg, 0, sizeof(req->cfg));

	if (req->param_flags & mask)
		req->cfg.MeshRetryTimeout = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshConfirmTimeout = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshHoldingTimeout = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshMaxPeerLinks = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshMaxRetries = (u8)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshTTL = (u8)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.element_ttl = (u8)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshHWMPmaxPREQretries = (u8)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.path_refresh_time = (u32)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.min_discovery_timeout = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshHWMPactivePathTimeout = (u32)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshHWMPpreqMinInterval = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshHWMPperrMinInterval = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.MeshHWMPnetDiameterTraversalTime = (u16)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.rssi_threshold = (s32)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.plink_timeout = (u32)value_for_set;
	if (req->param_flags & (mask <<= 1))
		req->cfg.beacon_interval = (u16)value_for_set;

	if_nl_send(
		NL60211_PLC_SET_MPARA,
		if_idx,
		sizeof(struct nl60211_plcsetmpara_req));

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_plcsetmpara_res *)nlres->buf;
	printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
	printf("if_index    = %d\n", nlres->if_index);
	printf("return_code = %d\n", res->return_code);
	return 0;
}

int do_plcdumpsta(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request

	//response
	struct nl60211msg *nlres;
	struct nl60211_plcdumpsta_res *res;
	//int i, temp;

	if_nl_send(NL60211_PLC_DUMP_STA, if_idx, 0);
	printf("%-21s %-14s %-10s %-10s\n",
	       "DA", "plink_state", "llid", "plid");

	while (1) {
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
		res = (struct nl60211_plcdumpsta_res *)nlres->buf;
		if (res->return_code < 0)
			break;
		//printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
		//printf("if_index    = %d\n", nlres->if_index);
		//printf("return_code = %d\n", res->return_code);
		printf("%02X:%02X:%02X:%02X:%02X:%02X     ",
		       res->addr[0], res->addr[1], res->addr[2],
		       res->addr[3], res->addr[4], res->addr[5]);
		printf("0x%04x         %-10d %-10d\n",
		       res->plink_state, res->llid, res->plid);
	}
	return 0;
}

int do_plcdumpmpath(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request

	//response
	struct nl60211msg *nlres;
	struct nl60211_plcdumpmpath_res *res;
	//int i, temp;

	if_nl_send(NL60211_PLC_DUMP_MPATH, if_idx, 0);
	printf("%-21s %-21s %-6s %-6s %-10s %-6s %-7s\n",
	       "DA", "NEXT_HOP", "SN", "METRIC", "EXPTIME", "FLAGS", "IS_ROOT");

	while (1) {
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
		res = (struct nl60211_plcdumpmpath_res *)nlres->buf;
		if (res->return_code < 0)
			break;
		printf("%02X:%02X:%02X:%02X:%02X:%02X     ",
		       res->da[0], res->da[1], res->da[2],
		       res->da[3], res->da[4], res->da[5]);
		printf("%02X:%02X:%02X:%02X:%02X:%02X     ",
		       res->next_hop[0], res->next_hop[1], res->next_hop[2],
		       res->next_hop[3], res->next_hop[4], res->next_hop[5]);
		printf("%-6d %-6d %-10ld 0x%04x %-6d\n",
		       res->sn, res->metric, res->exp_time,
		       res->flags, res->is_root);
	}
	return 0;
}


static const struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
} cmds[] = {
	{ STR_CTRL,         do_ctrl },
	{ STR_GETMESHID,    do_getmeshid },
	{ STR_SETMESHID,    do_setmeshid },
	{ STR_RECV,         do_recv },
	{ STR_RECV_ONCE,    do_recvonce },
	{ STR_RECV_CANCEL,  do_recvcancel },
	{ STR_PLCSEND,      do_sendplc },
	{ STR_WIFISEND,     do_sendwifi },
	{ STR_FLOODSEND,    do_sendflood },
	{ STR_BESTSEND,     do_sendbest },
	{ STR_GETSA,        do_getsa },
	{ STR_ADDMPATH,     do_addmpath },
	{ STR_DELMPATH,     do_delmpath },
	{ STR_SETMPATH,     do_setmpath },
	{ STR_GETMPATH,     do_getmpath },
	{ STR_DUMPMPATH,    do_dumpmpath },
	{ STR_PLCGETMETRIC, do_plcgetmetric },
	{ STR_PLCSETMETRIC, do_plcsetmetric },
	{ STR_PLCGETMPARA,  do_plcgetmpara },
	{ STR_PLCSETMPARA,  do_plcsetmpara },
	{ STR_PLCDUMPSTA,   do_plcdumpsta },
	{ STR_PLCDUMPMPATH, do_plcdumpmpath },
	{ 0 }
};

static int do_cmd(int argc, char **argv)
{
	const struct cmd *c;

	for (c = cmds; c->cmd; ++c) {
		if (matches(argv[0], c->cmd) == 0)
			return c->func(argc - 1, argv + 1);
	}

	fprintf(stderr, "Object \"%s\" is unknown\n", argv[0]);
	return EXIT_FAILURE;
}

THREAD_HANDLE_t gRxThread;

void *Rx_Thread(void *arg)
{
	printf("Rx_Thread() start, getpid() = %d\n", getpid());
	{
		//request
		//response
		struct nl60211msg *nlres;
		struct nl60211_getmeshid_res *res;
		
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
		res = (struct nl60211_getmeshid_res *)nlres->buf;
		printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
		printf("nlmsg_pid   = %d\n", nlres->nl_msghdr.nlmsg_pid);
		printf("if_index    = %d\n", nlres->if_index);
		printf("return_code = %d\n", res->return_code);
		printf("id_len	    = %d\n", res->id_len);
		printf("id	    = %s\n", res->id);
	}
	return 0;
}

void self_test(void)
{
	int retVal;

	retVal = LibThread_NewHandle(&gRxThread);
	BASIC_ASSERT(retVal == 0);


	retVal = LibThread_Create(gRxThread, Rx_Thread);
	BASIC_ASSERT(retVal == 0);

	usleep((useconds_t)(1000 * 10));

	if_nl_send(NL60211_GETMESHID, nametoindex("br0"), 0);


	LibThread_WaitThread(gRxThread);


	retVal = LibThread_DestroyHandle(gRxThread);
	BASIC_ASSERT(retVal == 0);

	REMOVE_UNUSED_WRANING(retVal);
}


int main(int argc, char **argv)
{
	int ret;

	printf("argc=%d\n", argc);
	printf("argv[0]=%s\n", argv[0]);
	if (argc >= 2)
		printf("argv[1]=%s\n", argv[1]);

	if (argc < 3) {
		ret = if_nl_init();
		if (ret) {
			fprintf(stderr, "if_nl_init() error, ret = %d\n", ret);
			return ret;
		}
		fprintf(stderr, "Too few arguments, exit...\n");
		//self_test();
		if_nl_deinit();
		return -1;
	}

	ret = if_nl_init();
	if (ret)
		return ret;

	do_cmd(argc - 1, argv + 1);

	if_nl_deinit();
	return 0;
}

