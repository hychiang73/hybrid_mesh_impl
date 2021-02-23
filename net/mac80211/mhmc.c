
#include <net/mac80211.h>
#include <net/cfg80211.h>

#include "mesh.h"
#include "mhmc.h"

int mhmc_parse_before_deliver(struct sk_buff *skb)
{
	struct ethhdr *ether;

	skb_reset_mac_header(skb);
	//hmc_print_skb(skb, "mhmc_parse_before_deliver", 0);

	ether = eth_hdr(skb);
	//pr_info("Protocol: %x\n", htons(ether->h_proto));

	if (htons(ether->h_proto) == 0xAA55) {
		pr_info("protocl is 0xAA55, call netif_receive_skb directly");
		memset(skb->cb, 0, sizeof(skb->cb));
		netif_receive_skb(skb);
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(mhmc_parse_before_deliver);

void mhmc_print_skb(struct sk_buff *skb, const char *type, int offset)
{
#if 0
	size_t len;
	int rowsize = 16;
	int i, l, linelen, remaining;
	int li = 0;
	u8 *data, ch;

	data = (u8 *)skb_mac_header(skb);
	//data = (u8 *) skb->head;

	if (skb_is_nonlinear(skb))
		len = skb->data_len;
	else
		len = skb->len;

	if (len > 256)
		len = 256;

	remaining = len + 2 + offset;
	pr_info("Packet hex dump (len = %ld):\n", len);
	pr_info("============== %s ==============\n", type);
	for (i = 0; i < len; i += rowsize) {
		pr_info("%06d\t", li);

		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		for (l = 0; l < linelen; l++) {
			ch = data[l];
			pr_cont("%02X ", (uint32_t)ch);
		}

		data += linelen;
		li += 10;

		pr_cont("\n");
	}
	pr_info("====================================\n");
#endif
}
