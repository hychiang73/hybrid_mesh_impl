#include "mac60211.h"

struct net_bridge_hmc *plc;
struct proc_dir_entry *proc_dir_plc;

static struct workqueue_struct *sbeacon_wq;
static struct delayed_work sbeacon_work;

static ssize_t plc_proc_test_read(struct file *pfile, char __user *buf, size_t size, loff_t *pos);
static ssize_t plc_proc_test_write(struct file *pfile, const char *buf, size_t size, loff_t *pos);
static int plc_br_hmc_rx(struct sk_buff *skb);
void plc_pkt_hex_dump(struct sk_buff *skb, const char* type, int offset);

struct file_operations proc_plc_fops = {
    .read = plc_proc_test_read,
    .write = plc_proc_test_write,
};

struct net_bridge_hmc_ops plc_br_hmc_ops = {
    .rx = plc_br_hmc_rx,
};

static int plc_br_hmc_rx(struct sk_buff *skb)
{
    TRACE();
    return ak60211_rx_handler(skb);
}

static int plc_br_hmc_alloc(void) 
{
    plc = br_hmc_alloc(&plc_br_hmc_ops);

    if (!plc) {
        pr_err("plc is null\n");
        return -ENOMEM;
    }

    plc->egress = HMC_PORT_PLC;

    cf60211_get_dev(plc);
    return 0;
}

void plc_pkt_hex_dump(struct sk_buff *skb, const char* type, int offset)
{
        size_t len;
        int rowsize = 16;
        int i, l, linelen, remaining;
        int li = 0;
        u8 *data, ch; 

        data = (u8 *) skb_mac_header(skb);
       //data = (u8 *) skb->head;

        if (skb_is_nonlinear(skb)) {
                len = skb->data_len;
        } else {
                len = skb->len;
        }

        remaining = len + 2 + offset;
        printk("Packet hex dump (len = %ld):\n", len);
        printk("============== %s ==============\n", type);
        for (i = 0; i < len; i += rowsize) {
                printk("%06d\t", li);

                linelen = min(remaining, rowsize);
                remaining -= rowsize;

                for (l = 0; l < linelen; l++) {
                        ch = data[l];
                        printk(KERN_CONT "%02X ", (uint32_t) ch);
                }

                data += linelen;
                li += 10; 

                printk(KERN_CONT "\n");
        }
        printk("====================================\n");
}
EXPORT_SYMBOL(plc_pkt_hex_dump);

static void plc_gen_sbeacon(struct plc_packet_union *buff)
{
    char meshid[MESHID_SIZE] = {0};
    meshid[0] = 'A';
    meshid[1] = 'k';
    meshid[2] = 'i';
    meshid[3] = 'r';
    meshid[4] = 'a';
    meshid[5] = 'N';
    meshid[6] = 'e';
    meshid[7] = 't';
    
    buff->plchdr.framectl = 0x0080;
    buff->plchdr.duration_id = 0;

    buff->plchdr.machdr.h_addr1[0] = 0xff;
    buff->plchdr.machdr.h_addr1[1] = 0xff;
    buff->plchdr.machdr.h_addr1[2] = 0xff;
    buff->plchdr.machdr.h_addr1[3] = 0xff;
    buff->plchdr.machdr.h_addr1[4] = 0xff;
    buff->plchdr.machdr.h_addr1[5] = 0xff;
    buff->plchdr.machdr.h_addr2[0] = 0x0;
    buff->plchdr.machdr.h_addr2[1] = 0x0;
    buff->plchdr.machdr.h_addr2[2] = 0x0;
    buff->plchdr.machdr.h_addr2[3] = 0x0;
    buff->plchdr.machdr.h_addr2[4] = 0x0;
    buff->plchdr.machdr.h_addr2[5] = 0x0;
    buff->plchdr.machdr.h_addr3[0] = 0xff;
    buff->plchdr.machdr.h_addr3[1] = 0xff;
    buff->plchdr.machdr.h_addr3[2] = 0xff;
    buff->plchdr.machdr.h_addr3[3] = 0xff;
    buff->plchdr.machdr.h_addr3[4] = 0xff;
    buff->plchdr.machdr.h_addr3[5] = 0xff;
    buff->plchdr.machdr.h_addr4[0] = 0x0;
    buff->plchdr.machdr.h_addr4[1] = 0x0;
    buff->plchdr.machdr.h_addr4[2] = 0x0;
    buff->plchdr.machdr.h_addr4[3] = 0x0;
    buff->plchdr.machdr.h_addr4[4] = 0x0;
    buff->plchdr.machdr.h_addr4[5] = 0x0;
    buff->plchdr.machdr.h_addr5[0] = 0x0;
    buff->plchdr.machdr.h_addr5[1] = 0x0;
    buff->plchdr.machdr.h_addr5[2] = 0x0;
    buff->plchdr.machdr.h_addr5[3] = 0x0;
    buff->plchdr.machdr.h_addr5[4] = 0x0;
    buff->plchdr.machdr.h_addr5[5] = 0x0;
    buff->plchdr.machdr.h_addr6[0] = 0x0;
    buff->plchdr.machdr.h_addr6[1] = 0x0;
    buff->plchdr.machdr.h_addr6[2] = 0x0;
    buff->plchdr.machdr.h_addr6[3] = 0x0;
    buff->plchdr.machdr.h_addr6[4] = 0x0;
    buff->plchdr.machdr.h_addr6[5] = 0x0;

    buff->plchdr.fn = 0;
    buff->plchdr.sn = 0;
    
    buff->un.beacon.meshid_elem.elemid = 114;
    buff->un.beacon.meshid_elem.len = MESHID_SIZE;
    memset(buff->un.beacon.meshid_elem.meshid, 0, MESHID_SIZE);
    memcpy(buff->un.beacon.meshid_elem.meshid, meshid, MESHID_SIZE);       // max meshid size copy
    
    buff->un.beacon.meshconf_elem.elemid = 113;
    buff->un.beacon.meshconf_elem.len = 7;
    buff->un.beacon.meshconf_elem.psel_protocol = 1;
    buff->un.beacon.meshconf_elem.psel_metric = 0;
    buff->un.beacon.meshconf_elem.congestion_ctrl_mode = 0;
    buff->un.beacon.meshconf_elem.sync_method = 0;
    buff->un.beacon.meshconf_elem.auth_protocol = 0;
    buff->un.beacon.meshconf_elem.mesh_formation.connected_to_gate = 0;
    buff->un.beacon.meshconf_elem.mesh_formation.num_of_peerings = 0;
    buff->un.beacon.meshconf_elem.mesh_formation.connected_as = 0;
    buff->un.beacon.meshconf_elem.mesh_cap.accepting_addi_mesh_peerings = 1;
    buff->un.beacon.meshconf_elem.mesh_cap.mcca_sup = 0;
    buff->un.beacon.meshconf_elem.mesh_cap.mcca_en = 0;
    buff->un.beacon.meshconf_elem.mesh_cap.forwarding = 1;
    buff->un.beacon.meshconf_elem.mesh_cap.mbca_en = 0;
    buff->un.beacon.meshconf_elem.mesh_cap.tbtt_adjusting = 0;
    buff->un.beacon.meshconf_elem.mesh_cap.ps = 0;
    buff->un.beacon.meshconf_elem.mesh_cap.reserved = 0;
}

void plc_fill_ethhdr(u8 *st, const u8 *da, const u8 *sa, u16 type)
{
    memcpy(st, da, ETH_ALEN);
    st += 6;
    memcpy(st, sa, ETH_ALEN);
    st += 6;
    memcpy(st, &type, 2);
}

static void plc_send_beacon(void)
{
    struct sk_buff *nskb;    
    struct plc_packet_union sbeacon;
    int beacon_len = sizeof(struct ethhdr) + sizeof(struct plc_hdr) + sizeof(struct beacon_pkts);
    u8 *pos;

    TRACE();

    // beacon packet size is 92 bytes
    nskb = dev_alloc_skb(2 + beacon_len + 2);
    if (!nskb) {
        hmc_err("no space to allocate");
        return;
    }

    plc_gen_sbeacon(&sbeacon);

    skb_reserve(nskb, 2);

    pos = skb_put_zero(nskb, beacon_len);
    plc_fill_ethhdr((u8 *)&sbeacon, broadcast_addr, plc->br_addr, ntohs(0xAA55));

    memcpy(sbeacon.plchdr.machdr.h_addr2, plc->br_addr, ETH_ALEN);
    memcpy(sbeacon.plchdr.machdr.h_addr4, plc->br_addr, ETH_ALEN);

    memcpy(pos, &sbeacon, beacon_len);

    skb_reset_mac_header(nskb);

    plc_pkt_hex_dump(nskb, "plc_beacon_send", 0);

    br_hmc_forward(nskb, plc);

}

static void plc_sbeacon_wq(struct work_struct *work)
{
    plc_send_beacon();
    if (!queue_delayed_work(sbeacon_wq, &sbeacon_work, msecs_to_jiffies(SBEACON_DELAY)))
		hmc_err("sbeacon was already on queue\n");
}

static void sbeacon_wq_deinit(void)
{
    TRACE();

    cancel_delayed_work_sync(&sbeacon_work);
	flush_workqueue(sbeacon_wq);
    hmc_info("sbeacon send cancel");
}

static void sbeacon_wq_init(void)
{
    TRACE();

    sbeacon_wq = alloc_workqueue("sbeacon", WQ_MEM_RECLAIM, 0);

    WARN_ON(!sbeacon_wq);

    INIT_DELAYED_WORK(&sbeacon_work, plc_sbeacon_wq);
    plc_send_beacon();

    if (!queue_delayed_work(sbeacon_wq, &sbeacon_work, msecs_to_jiffies(SBEACON_DELAY)))
		hmc_err("sbeacon was already on queue\n");

}

static ssize_t plc_proc_test_read(struct file *pfile, char __user *buf, size_t size, loff_t *pos) 
{
    TRACE();

    if (*pos != 0) {
        return 0;
    }

    return 0;
}

static ssize_t plc_proc_test_write(struct file *pfile, const char *ubuf, size_t size, loff_t *pos) 
{
#define MAX_BUF_WMAX    20
    static bool sbeacon_flag = false;
    char buf[MAX_BUF_WMAX];

    // TRACE();

    if (*pos >0 || size > MAX_BUF_WMAX) {
        return -EFAULT;
    }
    if (copy_from_user(buf, ubuf, size)) {
        return -EFAULT;
    }

    // beacon start
    if (!memcmp(buf,"beacon", size-1)) {
        sbeacon_flag = !sbeacon_flag;
        if (sbeacon_flag) {
            sbeacon_wq_init();
        } else {
            sbeacon_wq_deinit();
        }
    }

    return size;
}

static void plc_proc_init(void) 
{
    struct proc_dir_entry *node;

    TRACE();

    proc_dir_plc = proc_mkdir("hmc_plc", NULL);
    node = proc_create("plc", 0666, proc_dir_plc, &proc_plc_fops);
    if (!node) {
        hmc_err("Failed to create proc node");
        return;
    }
    //hmc_info("beacon size:%ld, %ld, %ld, %ld", sizeof(struct beacon_packet), sizeof(struct plc_hdr), sizeof(struct meshidhdr), sizeof(struct meshconfhdr));
}

static int __init plc_init(void)
{
    int ret = 0;

    TRACE();

    plc_br_hmc_alloc();
    plc_proc_init();

    return ret;
}

static void __exit plc_deinit(void)
{
    TRACE();
    remove_proc_entry("plc", proc_dir_plc);
    remove_proc_entry("hmc_plc", NULL);

    if (sbeacon_wq != NULL) {
        cancel_delayed_work_sync(&sbeacon_work);
	    flush_workqueue(sbeacon_wq);
	    destroy_workqueue(sbeacon_wq);
    }
    return;
}

module_init(plc_init);
module_exit(plc_deinit);
MODULE_AUTHOR("AkiraNET");
MODULE_DESCRIPTION("plc mesh core");
MODULE_LICENSE("GPL");

