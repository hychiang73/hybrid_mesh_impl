/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2021 AkiraNET Corporation
 */

#ifndef MAC60211_H
#define MAC60211_H

#include "../hmc/hmc.h"

void plc_fill_ethhdr(u8 *st, const u8 *da, const u8 *sa, u16 type);
int plc_hmc_rx(struct sk_buff *skb, struct sk_buff *nskb);
int plc_hmc_preq_queue(const u8 *addr);
void plc_get_meshid(u8 *mesh_id, size_t *mesh_id_len);
void plc_set_meshid(u8 *mesh_id, size_t mesh_id_len);

int ak60211_nexthop_resolved(struct sk_buff *skb, u8 iface_id);
#endif /* MAC60211_H */
