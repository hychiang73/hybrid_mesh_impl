
#ifndef _EVERYTHING_H_
#define _EVERYTHING_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h> // for if_nametoindex()
#include <errno.h> // for perror()
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>

#include <unistd.h> // unsigned int sleep(unsigned int seconds);   http://man7.org/linux/man-pages/man3/usleep.3.html

#include "nl60211_uapi.h"

#include <My_Basics.hpp>
#include "lib.h"

int if_nl_send(uint16_t type, unsigned int if_index, uint32_t buf_len);
int if_nl_recv(void);
struct nl60211skmsg {
	struct msghdr       sk_msghdr;
	struct iovec        iov;
	struct nl60211msg   nl_msg;
};
extern struct nl60211skmsg sk_msg_send;
extern struct nl60211skmsg sk_msg_recv;

void self_test_proc(u32 ctrl_code, unsigned int if_idx);

#endif //_EVERYTHING_H_

