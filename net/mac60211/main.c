
#include "mac60211.h"
#include "ak60211_mesh_private.h"
#include "nl60211.h"
#include "../net/bridge/br_hmc.h"

bool plc_dbg = false;

struct net_bridge_hmc *plc;
struct proc_dir_entry *proc_dir_plc;
/* work queue */
static struct workqueue_struct *preq_wq;
static struct work_struct preq_work;

static struct workqueue_struct *sbeacon_wq;
static struct delayed_work sbeacon_work;

static ssize_t plc_proc_test_read(struct file *pfile, char __user *buf, size_t size, loff_t *pos);
static ssize_t plc_proc_test_write(struct file *pfile, const char *buf, size_t size, loff_t *pos);
static int plc_br_hmc_rx(struct sk_buff *skb);
void ak60211_mpath_queue_preq_ops(struct net_bridge_hmc *h);
void plc_pkt_hex_dump(struct sk_buff *skb, const char* type, int offset);

struct file_operations proc_plc_fops = {
    .read = plc_proc_test_read,
    .write = plc_proc_test_write,
};

struct net_bridge_hmc_ops plc_br_hmc_ops = {
    .rx = plc_br_hmc_rx,
    .queue_preq = ak60211_mpath_queue_preq_ops,//ak60211_mpath_queue_preq_test,
};

static int plc_br_hmc_rx(struct sk_buff *skb)
{
    return ak60211_rx_handler(skb);
}

static int plc_br_hmc_alloc(void) 
{
    plc = br_hmc_alloc("plc", &plc_br_hmc_ops);

    if (!plc) {
        plc_err("plc is null\n");
        return -ENOMEM;
    }
    plc->egress = HMC_PORT_PLC;

    return 0;
}

void plc_fill_ethhdr(u8 *st, const u8 *da, const u8 *sa, u16 type)
{
    memcpy(st, da, ETH_ALEN);
    st += 6;
    memcpy(st, sa, ETH_ALEN);
    st += 6;
    memcpy(st, &type, 2);
}

void ak60211_mpath_queue_preq_test(struct net_bridge_hmc *h)
{
    PLC_TRACE();

    /* obtain the path information from br-hmc table */
    memcpy(plc->path->dst, h->path->dst, ETH_ALEN);
    plc->path->flags = h->path->flags;
    plc->path->sn = h->path->sn;
    plc->path->metric = h->path->metric;

    /* create a workqueue to handle prep */
    schedule_work(&preq_work);
}

void ak60211_mpath_queue_preq_ops(struct net_bridge_hmc *h)
{
    ak60211_mpath_queue_preq_new(h->path);
}

static void plc_sbeacon_wq(struct work_struct *work)
{
    plc_send_beacon();
    if (!queue_delayed_work(sbeacon_wq, &sbeacon_work, msecs_to_jiffies(SBEACON_DELAY)))
		plc_err("sbeacon was already on queue\n");
}

static void sbeacon_wq_deinit(void)
{
    PLC_TRACE();

    cancel_delayed_work_sync(&sbeacon_work);
	flush_workqueue(sbeacon_wq);
    plc_info("sbeacon send cancel\n");
}

static void sbeacon_wq_init(void)
{
    PLC_TRACE();

    sbeacon_wq = alloc_workqueue("sbeacon", WQ_MEM_RECLAIM, 0);

    WARN_ON(!sbeacon_wq);

    INIT_DELAYED_WORK(&sbeacon_work, plc_sbeacon_wq);
    plc_send_beacon();

    if (!queue_delayed_work(sbeacon_wq, &sbeacon_work, msecs_to_jiffies(SBEACON_DELAY)))
		plc_err("sbeacon was already on queue\n");

}

static ssize_t plc_proc_test_read(struct file *pfile, char __user *buf, size_t size, loff_t *pos) 
{
    PLC_TRACE();

    if (*pos != 0) {
        return 0;
    }

    return 0;
}

static ssize_t plc_proc_test_write(struct file *pfile, const char *ubuf, size_t size, loff_t *pos) 
{
#define MAX_BUF_WMAX    20
    static bool sbeacon_flag = false;
    static u32 hmc_sn = 0;
    char buf[MAX_BUF_WMAX];
    u8 jetson2[ETH_ALEN] = {0x00, 0x04, 0x4b, 0xe6, 0xec, 0x3d};

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

    if (!memcmp(buf, "preq", size-1)) {
        // ak60211_mpath_queue_preq(jetson2, ++hmc_sn);
        memcpy(plc->path->dst, jetson2, ETH_ALEN);
        plc->path->sn = ++hmc_sn;
        ak60211_mpath_queue_preq_ops(plc);
    }

    if (!memcmp(buf, "debug", size-1)) {
        plc_dbg = !plc_dbg;
        if (plc_dbg) {
            pr_info("PLC: (%s, %d): plc_dbg on\n", __func__, __LINE__);
        } else {
            pr_info("PLC: (%s, %d): plc_dbg off\n", __func__, __LINE__);
        }
    }
    return size;
}

static void plc_proc_init(void) 
{
    struct proc_dir_entry *node;

    PLC_TRACE();

    proc_dir_plc = proc_mkdir("hmc_plc", NULL);
    node = proc_create("plc", 0666, proc_dir_plc, &proc_plc_fops);
    if (!node) {
        plc_err("Failed to create proc node\n");
        return;
    }
}

static void ak60211_mesh_init_test(void)
{
	/* Init workqueue */
	preq_wq = create_singlethread_workqueue("preq_wq");
	WARN_ON(!preq_wq);
	INIT_WORK(&preq_work, ak60211_preq_test_wq);
}

void ak60211_mesh_exit_test(void)
{
	if (preq_wq != NULL) {
		flush_workqueue(preq_wq);
		destroy_workqueue(preq_wq);
	}
}

static int __init plc_init(void)
{
    int ret = 0; 
    bool ifmesh = 0;

    PLC_TRACE();

    br_hmc_init();

    nl60211_netlink_init();

    plc_br_hmc_alloc();
    plc_proc_init();

    ifmesh = ak60211_mesh_init("AkiraNet", plc->br_addr);
    if (!ifmesh) {
        plc_err("mesh interface %pM init fail\n", plc->br_addr);
    } else {
        plc_info("mesh interface %pM init success\n", plc->br_addr);
    }
    ak60211_mesh_init_test();

    return ret;
}

static void __exit plc_deinit(void)
{
    PLC_TRACE();
    br_hmc_deinit();
    remove_proc_entry("plc", proc_dir_plc);
    remove_proc_entry("hmc_plc", NULL);

    ak60211_mesh_deinit();
    if (sbeacon_wq != NULL) {
        cancel_delayed_work_sync(&sbeacon_work);
	    flush_workqueue(sbeacon_wq);
	    destroy_workqueue(sbeacon_wq);
    }

    nl60211_netlink_exit();
    ak60211_mesh_exit_test();
    return;
}

module_init(plc_init);
module_exit(plc_deinit);
MODULE_AUTHOR("AkiraNET");
MODULE_DESCRIPTION("plc mesh core");
MODULE_LICENSE("GPL");

