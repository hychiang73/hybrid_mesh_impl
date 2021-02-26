/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2021 AkiraNET Corporation
 */

#ifndef MAC60211_H
#define MAC60211_H

#include "hmc.h"

void plc_fill_ethhdr(u8 *st, const u8 *da, const u8 *sa, u16 type);
int plc_hmc_rx(struct sk_buff *skb, struct sk_buff *nskb);
int plc_hmc_preq_queue(const u8 *addr);

#endif /* MAC60211_H */
