
#include "mac60211.h"
#include "ak60211_mesh_private.h"
#include "nl60211.h"
#include "hmc.h"

bool plc_dbg;

struct proc_dir_entry *proc_dir_plc;

static struct workqueue_struct *sbeacon_wq;
static struct delayed_work sbeacon_work;

static ssize_t plc_proc_test_read(struct file *pfile, char __user *buf,
				  size_t size, loff_t *pos);
static ssize_t plc_proc_test_write(struct file *pfile, const char *buf,
				   size_t size, loff_t *pos);

const struct file_operations proc_plc_fops = {
	.read = plc_proc_test_read,
	.write = plc_proc_test_write,
};

int plc_hmc_rx(struct sk_buff *skb)
{
	return ak60211_rx_handler(skb);
}
EXPORT_SYMBOL(plc_hmc_rx);

int plc_hmc_preq_queue(const u8 *addr)
{
	pr_info("%s\n", __func__);
	return ak60211_mpath_queue_preq(addr);
}
EXPORT_SYMBOL(plc_hmc_preq_queue);

void plc_fill_ethhdr(u8 *st, const u8 *da, const u8 *sa, u16 type)
{
	memcpy(st, da, ETH_ALEN);
	st += 6;
	memcpy(st, sa, ETH_ALEN);
	st += 6;
	memcpy(st, &type, 2);
}

static void plc_sbeacon_wq(struct work_struct *work)
{
	plc_send_beacon();
	if (!queue_delayed_work(sbeacon_wq, &sbeacon_work,
				msecs_to_jiffies(SBEACON_DELAY)))
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

	if (!queue_delayed_work(sbeacon_wq, &sbeacon_work,
				msecs_to_jiffies(SBEACON_DELAY)))
		plc_err("sbeacon was already on queue\n");
}

static ssize_t plc_proc_test_read(struct file *pfile, char __user *buf,
				  size_t size, loff_t *pos)
{
	PLC_TRACE();

	if (*pos != 0)
		return 0;

	return 0;
}

static ssize_t plc_proc_test_write(struct file *pfile, const char *ubuf,
				   size_t size, loff_t *pos)
{
#define MAX_BUF_WMAX	20
	static bool sbeacon_flag;
	char buf[MAX_BUF_WMAX];

	if (*pos > 0 || size > MAX_BUF_WMAX)
		return -EFAULT;

	if (copy_from_user(buf, ubuf, size))
		return -EFAULT;

	/* beacon start */
	if (!memcmp(buf, "beacon", size - 1)) {
		sbeacon_flag = !sbeacon_flag;
		if (!sbeacon_flag)
			sbeacon_wq_init();
		else
			sbeacon_wq_deinit();
	}

	if (!memcmp(buf, "debug", size - 1)) {
		plc_dbg = !plc_dbg;
		if (plc_dbg)
			pr_info("PLC: (%s, %d): plc_dbg on\n",
				__func__, __LINE__);
		else
			pr_info("PLC: (%s, %d): plc_dbg off\n",
				__func__, __LINE__);
	}
	return size;
}

static void plc_proc_init(void)
{
	struct proc_dir_entry *node;

	PLC_TRACE();

	proc_dir_plc = proc_mkdir("hmc_plc", NULL);
	node = proc_create("plc", 0644, proc_dir_plc, &proc_plc_fops);
	if (!node) {
		plc_err("Failed to create proc node\n");
		return;
	}
}

static int __init plc_init(void)
{
	int ret = 0;
	u8 local_addr[ETH_ALEN] = {0};
	bool ifmesh = 0;

	PLC_TRACE();

	if (hmc_core_init() < 0) {
		hmc_err("Failed to initialize HMC\n");
		return -ENOMEM;
	}

	nl60211_netlink_init();

	plc_proc_init();

	hmc_get_dev_addr(local_addr);

	ifmesh = ak60211_mesh_init("AkiraNet", local_addr);
	sbeacon_wq_init();

	if (!ifmesh)
		plc_err("mesh interface %pM init fail\n", local_addr);
	else
		plc_info("mesh interface %pM init success\n", local_addr);

	return ret;
}

static void __exit plc_deinit(void)
{
	PLC_TRACE();

	hmc_core_exit();

	remove_proc_entry("plc", proc_dir_plc);
	remove_proc_entry("hmc_plc", NULL);

	ak60211_mesh_deinit();

	if (sbeacon_wq) {
		cancel_delayed_work_sync(&sbeacon_work);
		flush_workqueue(sbeacon_wq);
		destroy_workqueue(sbeacon_wq);
	}

	nl60211_netlink_exit();
}

module_init(plc_init);
module_exit(plc_deinit);
MODULE_AUTHOR("AkiraNET");
MODULE_DESCRIPTION("plc mesh core");
MODULE_LICENSE("GPL");

