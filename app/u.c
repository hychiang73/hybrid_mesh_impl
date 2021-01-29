#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h> // for if_nametoindex()
#include <errno.h> // for perror()

#define STR_DEBUG           "debug"
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
//
//ref: netlink.h
//
#define NETLINK_60211 (MAX_LINKS-1)
// nlmsg_type[15:8] is snap command flag
#define NL60211FLAG_NO_RESPONSE 0x8000
// nlmsg_type[7:0] is snap command enum
enum {
	NL60211_DEBUG = 0,     // snap debug       br0 ...
	NL60211_GETMESHID,     // snap getmeshid   br0
	NL60211_SETMESHID,     // snap setmeshid   br0 mymesh0
	NL60211_RECV,          // snap recv        br0
	NL60211_RECV_ONCE,     // snap recvonce    br0
	NL60211_RECV_CANCEL,   // snap recvcancel  br0
	NL60211_SEND_PLC,      // snap sendplc     br0 ff ff ff ff ff ff 11...
	NL60211_SEND_WIFI,     // snap sendwifi    br0 ff ff ff ff ff ff 11...
	NL60211_SEND_FLOOD,    // snap sendflood   br0 ff ff ff ff ff ff 11...
	NL60211_SEND_BEST,     // snap sendbest    br0 ff ff ff ff ff ff 11...
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

// This buffer is for tx & "rx".
//And it contains socket message header:"struct msghdr" for simplifying.
struct nl60211msg {
	struct nlmsghdr     nl_msghdr;

	// netlink payload
	unsigned int        if_index;
	uint8_t             buf[MAX_PAYLOAD];
};
struct nl60211skmsg {
	struct msghdr       sk_msghdr;
	struct iovec        iov;
	struct nl60211msg   nl_msg;
};

struct sockaddr_nl src_addr, dest_addr;
//struct nlmsghdr *nlh = NULL;
//struct iovec iov;
int sock_fd;
struct nl60211skmsg sk_msg;

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
	struct nl60211msg *msg = &(sk_msg.nl_msg);

	if (buf_len > MAX_PAYLOAD)
		return -1;

	msg->nl_msghdr.nlmsg_len =
		sizeof(struct nl60211msg) - MAX_PAYLOAD + buf_len;

	msg->nl_msghdr.nlmsg_pid = getpid();
	msg->nl_msghdr.nlmsg_flags = 0;
	msg->nl_msghdr.nlmsg_type = type;

	msg->if_index = if_index;

	// 2. add netlink message to iov
	sk_msg.iov.iov_base = (void *)msg;
	sk_msg.iov.iov_len = msg->nl_msghdr.nlmsg_len;

	// 3. combine iov to socket message iov
	sk_msg.sk_msghdr.msg_iov = &(sk_msg.iov);
	sk_msg.sk_msghdr.msg_iovlen = 1;

	// 4. set destination address
	sk_msg.sk_msghdr.msg_name = (void *)&dest_addr;
	sk_msg.sk_msghdr.msg_namelen = sizeof(dest_addr);

	//ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
	sendmsg(sock_fd, &(sk_msg.sk_msghdr), 0);
	return 0;
}

int if_nl_recv(void)
{
	struct nl60211msg *msg = &(sk_msg.nl_msg);

	sk_msg.iov.iov_base = (void *)msg;
	sk_msg.iov.iov_len = sizeof(struct nl60211msg);

	sk_msg.sk_msghdr.msg_iov = &(sk_msg.iov);
	sk_msg.sk_msghdr.msg_iovlen = 1;

	//ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
	recvmsg(sock_fd, &(sk_msg.sk_msghdr), 0);
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

static unsigned int nametoindex(char *name)
{
	unsigned int if_idx = (uint32_t)if_nametoindex(name);

	if (if_idx == 0) {
		fprintf(stderr, "Interface \"%s\" is unknown\n", name);
		exit(-1);
	}
	return if_idx;
}

int do_debug(int argc, char **argv)
{
	unsigned int if_idx = nametoindex(argv[0]);
	//request
	struct nl60211_debug_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_debug_res *res;
	int i;
	unsigned int temp;

	printf("debug start ... if = %s, idx = %d\n", argv[0], if_idx);
	argc--;
	argv++;
	req = (struct nl60211_debug_req *)sk_msg.nl_msg.buf;
	req->len = argc;
	for (i = 0; i < argc; i++) {
		if (sscanf(argv[i], "%x", &temp) == 0) {
			printf("Error: not a hex string!\n");
			exit(-1);
		}
		req->buf[i] = (uint8_t)temp;
	}
	if_nl_send(
		NL60211_DEBUG,
		if_idx,
		sizeof(req->len) +/*da,sa,ether_type,payload*/argc);

	do {
		printf("debug recv ......\n");
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg.nl_msg;
		res = (struct nl60211_debug_res *)nlres->buf;
		printf("nlmsg_type  = %d\n", nlres->nl_msghdr.nlmsg_type);
		printf("if_index    = %d\n", nlres->if_index);
		printf("return_code = %d\n", res->return_code);
		printf("len         = %d\n", res->len);
		for (i = 0; i < res->len; i++) {
			printf("%02X ", res->buf[i]);
			if ((i % 16) == 15)
				printf("\n");
		}
		printf("\n");
	} while (0);

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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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
	req = (struct nl60211_setmeshid_req *)sk_msg.nl_msg.buf;
	req->id_len = strlen(argv[1]);
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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
	unsigned int i, temp;

	printf("do_recv, idx = %d\n", if_idx);
	argc--;
	argv++;
	if (argc != 2) {
		printf("ether_type must be 2 bytes!\n");
		return -1;
	}
	req = (struct nl60211_recv_req *)sk_msg.nl_msg.buf;
	if (sscanf(argv[0], "%x", &temp) == 0) {
		printf("Error: not a hex string!\n");
		exit(-1);
	}
	req->ether_type[0] = (unsigned char)temp;
	if (sscanf(argv[1], "%x", &temp) == 0) {
		printf("Error: not a hex string!\n");
		exit(-1);
	}
	req->ether_type[1] = (unsigned char)temp;
	if_nl_send(NL60211_RECV_ONCE, if_idx, sizeof(struct nl60211_recv_req));

	do {
		printf("start recv ......\n");
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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
	unsigned int i, temp;

	printf("do_recv, idx = %d\n", if_idx);
	argc--;
	argv++;
	if (argc != 2) {
		printf("ether_type must be 2 bytes!\n");
		return -1;
	}
	req = (struct nl60211_recv_req *)sk_msg.nl_msg.buf;
	if (sscanf(argv[0], "%x", &temp) == 0) {
		printf("Error: not a hex string!\n");
		exit(-1);
	}
	req->ether_type[0] = (unsigned char)temp;
	if (sscanf(argv[1], "%x", &temp) == 0) {
		printf("Error: not a hex string!\n");
		exit(-1);
	}
	req->ether_type[1] = (unsigned char)temp;
	if_nl_send(NL60211_RECV_ONCE, if_idx, sizeof(struct nl60211_recv_req));

	do {
		printf("start recv ......\n");
		if_nl_recv();
		nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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

	req = (struct nl60211_sendplc_req *)sk_msg.nl_msg.buf;
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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

	req = (struct nl60211_sendwifi_req *)sk_msg.nl_msg.buf;
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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

	req = (struct nl60211_sendflood_req *)sk_msg.nl_msg.buf;
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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

	req = (struct nl60211_sendbest_req *)sk_msg.nl_msg.buf;
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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
	nlres = (struct nl60211msg *)&sk_msg.nl_msg;
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

static const struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
} cmds[] = {
	{ STR_DEBUG,        do_debug },
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

int main(int argc, char **argv)
{
	int ret;

	printf("argc=%d\n", argc);
	printf("argv[0]=%s\n", argv[0]);
	if (argc >= 2)
		printf("argv[1]=%s\n", argv[1]);

	if (argc < 3) {
		fprintf(stderr, "Too few arguments, exit...\n");
		return -1;
	}

	ret = if_nl_init();
	if (ret)
		return ret;

	do_cmd(argc - 1, argv + 1);

	if_nl_deinit();
	return 0;
}

