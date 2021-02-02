// SPDX-License-Identifier: GPL-2.0-only
/*Copyright (C) 2021 AkiraNET Corporation */

#ifndef NL60211_H
#define NL60211_H

#include <net/arp.h>
#include <net/ip.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netpoll.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <net/dsa.h>
#include <net/sock.h>
#include <linux/if_vlan.h>
#include <net/switchdev.h>
#include <net/net_namespace.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/netfilter_bridge.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/ieee80211.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>

#include "../bridge/br_private.h"

int nl60211_netlink_init(void);
void nl60211_netlink_exit(void);

#endif /* NL60211_H */
