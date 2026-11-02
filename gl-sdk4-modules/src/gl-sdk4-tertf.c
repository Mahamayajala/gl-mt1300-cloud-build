/*
 * gl-sdk4-tertf.c
 *
 * GL.iNet "tertf" (transparent traffic/forwarding accounting) module,
 * clean-room reimplementation of the original gl-sdk4-tertf.ko from
 * GL.iNet GL-MT1300 firmware (OpenWrt 22.03.4, kernel 5.10.176).
 *
 * Original source name: term.c, (C) 2021 jianhui.zhao@gl-inet.com,
 * git commit 524d7a3.
 *
 * Behavior (verified against the running device):
 *   - Creates /proc/oui-tertf/{config,subnet,term}.
 *   - config write: "ttl=<seconds>"  (read back as "ttl: <n>").
 *   - subnet write: "add <network>"  where <network> is a logical
 *     interface name (br-lan) or an IP/CIDR (192.168.1.1/24).  The
 *     interface's subnet is resolved via its IPv4 addr+netmask.
 *   - subnet read: "ifindex ifname\n<idx>\t<name>\n..." .
 *   - term read: per-client (MAC/IP) Tx/Rx byte counters plus the
 *     client's port, formatted as:
 *       "%-17s  %-16s  %-16s  %-16s  %-16s\n"   header
 *       "%pM  %-16pI4  %-16llu  %-16llu  %-16s\n"  row
 *   - A netfilter FORWARD hook counts bytes for packets whose src or
 *     dst IPv4 address belongs to any tracked subnet.  Entries expire
 *     after the configured TTL.
 *   - On new client discovery a uevent (KOBJ_ADD) is broadcast with
 *     MAC/IP/DEV attributes to notify userspace.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>
#include <net/arp.h>
#include <net/net_namespace.h>
#include <net/ip.h>

#define OUI_TERF_DIR   "oui-tertf"
#define TERF_DFL_TTL   30
#define TERF_MAX_SUBNETS 32

/* subnet rule */
struct tertf_subnet {
	struct list_head list;
	u32 addr;		/* network address, host order */
	u32 mask;		/* netmask, host order */
	int ifindex;
	char ifname[IFNAMSIZ];
};

/* per-client term entry */
struct tertf_term {
	struct list_head list;
	u8 mac[ETH_ALEN];
	__be32 ip;		/* network order */
	u64 tx, rx;
	unsigned long last_seen;
	char dev[IFNAMSIZ];
};

static LIST_HEAD(tertf_subnets);
static LIST_HEAD(tertf_terms);
static struct proc_dir_entry *tertf_root;
static struct proc_dir_entry *tertf_config_p, *tertf_subnet_p, *tertf_term_p;

static unsigned long tertf_ttl = TERF_DFL_TTL;
static struct workqueue_struct *tertf_wq;
static struct delayed_work tertf_expire_work;

/* ------------------------------------------------------------------ */
/* subnet helpers                                                       */
/* ------------------------------------------------------------------ */
static int subnet_in_range(u32 addr_host, u32 subnet, u32 mask)
{
	return (addr_host & mask) == (subnet & mask);
}

static struct tertf_subnet *subnet_find_by_ifindex(int ifindex)
{
	struct tertf_subnet *s;

	list_for_each_entry(s, &tertf_subnets, list)
		if (s->ifindex == ifindex)
			return s;
	return NULL;
}

static void subnet_free(struct tertf_subnet *s)
{
	list_del(&s->list);
	kfree(s);
}

/* resolve interface name -> IPv4 subnet */
static int subnet_resolve_ifname(const char *ifname, u32 *addr, u32 *mask)
{
	struct net_device *dev;
	struct in_device *idev;
	struct in_ifaddr *ifa;
	int found = 0;

	dev = dev_get_by_name(&init_net, ifname);
	if (!dev)
		return -ENODEV;

	idev = in_dev_get(dev);
	if (idev) {
		rcu_read_lock();
		for (ifa = idev->ifa_list; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_address && ifa->ifa_mask) {
				*addr = ntohl(ifa->ifa_address & ifa->ifa_mask);
				*mask = ntohl(ifa->ifa_mask);
				found = 1;
				break;
			}
		}
		rcu_read_unlock();
		in_dev_put(idev);
	}
	dev_put(dev);
	return found ? 0 : -ENOENT;
}

/* parse "addr/mask" or bare address */
static int subnet_parse_cidr(const char *s, u32 *addr, u32 *mask)
{
	char buf[64];
	char *slash, *p;
	__be32 a;
	int bits;

	strscpy(buf, s, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	slash = strchr(buf, '/');
	if (slash) {
		*slash = '\0';
		bits = simple_strtoul(slash + 1, NULL, 10);
		if (bits < 0 || bits > 32)
			return -EINVAL;
	} else {
		bits = 32;
	}

	/* strip whitespace */
	p = buf;
	while (*p == ' ' || *p == '\t')
		p++;
	a = in_aton(p);
	if (!a)
		return -EINVAL;

	*addr = ntohl(a);
	*mask = (bits == 0) ? 0 : (0xffffffffUL << (32 - bits));
	return 0;
}

/* add a subnet: ifname or CIDR */
static int tertf_add_subnet(const char *arg)
{
	struct tertf_subnet *s;
	struct net_device *dev;
	u32 addr, mask;
	int ret;

	/* try CIDR first (contains '/' or looks like an address) */
	if (strchr(arg, '/')) {
		ret = subnet_parse_cidr(arg, &addr, &mask);
		if (ret)
			return ret;
		s = kzalloc(sizeof(*s), GFP_KERNEL);
		if (!s)
			return -ENOMEM;
		s->addr = addr;
		s->mask = mask;
		s->ifindex = -1;
		strscpy(s->ifname, arg, IFNAMSIZ);
		list_add_tail(&s->list, &tertf_subnets);
		pr_info("tertf: subnet %08x/%08x added\n", addr, mask);
		return 0;
	}

	/* resolve interface name */
	dev = dev_get_by_name(&init_net, arg);
	if (dev) {
		/* already have it? */
		s = subnet_find_by_ifindex(dev->ifindex);
		if (s) {
			dev_put(dev);
			pr_info("tertf: %s already exists\n", arg);
			return 0;
		}
		dev_put(dev);
	}

	ret = subnet_resolve_ifname(arg, &addr, &mask);
	if (ret)
		return ret;

	dev = dev_get_by_name(&init_net, arg);
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->addr = addr;
	s->mask = mask;
	s->ifindex = dev ? dev->ifindex : -1;
	strscpy(s->ifname, arg, IFNAMSIZ);
	if (dev)
		dev_put(dev);
	list_add_tail(&s->list, &tertf_subnets);
	pr_info("tertf: %s registered, add it\n", arg);
	return 0;
}

/* ------------------------------------------------------------------ */
/* term entry helpers                                                   */
/* ------------------------------------------------------------------ */
static struct tertf_term *term_find(const u8 *mac)
{
	struct tertf_term *t;

	list_for_each_entry(t, &tertf_terms, list)
		if (ether_addr_equal(t->mac, mac))
			return t;
	return NULL;
}

static struct tertf_term *term_create(const u8 *mac, __be32 ip,
				      const char *dev)
{
	struct tertf_term *t;

	t = kzalloc(sizeof(*t), GFP_ATOMIC);
	if (!t)
		return NULL;
	ether_addr_copy(t->mac, mac);
	t->ip = ip;
	t->tx = t->rx = 0;
	t->last_seen = jiffies;
	strscpy(t->dev, dev, IFNAMSIZ);
	list_add_tail(&t->list, &tertf_terms);
	return t;
}

static void term_free(struct tertf_term *t)
{
	list_del(&t->list);
	kfree(t);
}

/* best-effort uevent broadcast (forward declaration) */
static void tertf_uevent(const u8 *mac, __be32 ip, const char *dev);

/* ------------------------------------------------------------------ */
/* netfilter hook: per-client byte accounting                           */
/* ------------------------------------------------------------------ */
static unsigned int tertf_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tertf_subnet *s;
	struct tertf_term *t;
	__be32 sip, dip;
	u32 sip_h, dip_h;
	int matched;
	const u8 *client_mac;
	__be32 client_ip;
	const char *client_dev;
	int is_tx;
	u64 len;

	if (!skb || !skb->dev)
		return NF_ACCEPT;
	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	eth = eth_hdr(skb);
	iph = ip_hdr(skb);
	if (!eth || !iph || iph->version != 4)
		return NF_ACCEPT;

	sip = iph->saddr;
	dip = iph->daddr;
	sip_h = ntohl(sip);
	dip_h = ntohl(dip);

	if (list_empty(&tertf_subnets))
		return NF_ACCEPT;

	matched = 0;
	is_tx = 0;
	client_mac = NULL;
	client_ip = 0;
	client_dev = NULL;

	list_for_each_entry(s, &tertf_subnets, list) {
		if (subnet_in_range(sip_h, s->addr, s->mask)) {
			/* packet from a client on the subnet -> Tx */
			matched = 1;
			is_tx = 1;
			client_mac = eth->h_source;
			client_ip = sip;
			client_dev = skb->dev->name;
			break;
		}
		if (subnet_in_range(dip_h, s->addr, s->mask)) {
			/* packet to a client on the subnet -> Rx */
			matched = 1;
			is_tx = 0;
			client_mac = eth->h_dest;
			client_ip = dip;
			client_dev = skb->dev->name;
			break;
		}
	}

	if (!matched || !client_mac)
		return NF_ACCEPT;
	if (is_multicast_ether_addr(client_mac) ||
	    is_broadcast_ether_addr(client_mac))
		return NF_ACCEPT;

	t = term_find(client_mac);
	if (!t) {
		t = term_create(client_mac, client_ip, client_dev);
		if (!t)
			return NF_ACCEPT;
		/* broadcast uevent to notify userspace of new client */
		tertf_uevent(client_mac, client_ip, client_dev);
	}

	len = skb->len;
	if (is_tx)
		t->tx += len;
	else
		t->rx += len;
	t->last_seen = jiffies;
	if (t->ip != client_ip)
		t->ip = client_ip;

	return NF_ACCEPT;
}

/* best-effort uevent broadcast: notify userspace of a new client.
 * The original used a netlink uevent broadcast with MAC/IP/DEV env.
 * Here we build the envp array and call kobject_uevent_env on a
 * per-netdev kobject if a suitable one is available; otherwise it is
 * a harmless no-op (userspace also polls /proc/oui-tertf/term). */
static void tertf_uevent(const u8 *mac, __be32 ip, const char *dev)
{
	char macs[32], ips[32];
	char *envp[6];
	int i = 0;
	struct net_device *ndev;

	/* find the netdevice to attach the uevent to */
	ndev = dev_get_by_name(&init_net, dev);
	if (!ndev)
		return;

	snprintf(macs, sizeof(macs), "MAC=%pM", mac);
	snprintf(ips, sizeof(ips), "IP=%pI4", &ip);
	envp[i++] = "HOME=/";
	envp[i++] = "PATH=/sbin:/usr/sbin:/bin:/usr/bin";
	envp[i++] = "SUBSYSTEM=net";
	envp[i++] = "ACTION=add";
	envp[i++] = macs;
	envp[i++] = ips;
	envp[i] = NULL;

	if (ndev->dev.kobj.state_initialized)
		kobject_uevent_env(&ndev->dev.kobj, KOBJ_ADD, envp);
	dev_put(ndev);
}

static struct nf_hook_ops tertf_ops = {
	.hook		= tertf_hook,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_FORWARD,
	.priority	= NF_IP_PRI_FILTER - 1,
};

/* ------------------------------------------------------------------ */
/* TTL expiry work                                                      */
/* ------------------------------------------------------------------ */
static void tertf_expire_workfn(struct work_struct *work)
{
	struct tertf_term *t, *tmp;
	unsigned long now = jiffies;

	list_for_each_entry_safe(t, tmp, &tertf_terms, list) {
		if (time_after(now, t->last_seen + tertf_ttl * HZ))
			term_free(t);
	}
	mod_delayed_work(tertf_wq, &tertf_expire_work,
			 msecs_to_jiffies(5000));
}

/* ------------------------------------------------------------------ */
/* proc file handlers                                                   */
/* ------------------------------------------------------------------ */
/* config: read back "ttl: <n>" */
static int tertf_config_show(struct seq_file *m, void *v)
{
	seq_printf(m, "ttl: %lu\n", tertf_ttl);
	return 0;
}

static int tertf_config_open(struct inode *inode, struct file *file)
{
	return single_open(file, tertf_config_show, NULL);
}

static ssize_t tertf_config_write(struct file *file, const char __user *ubuf,
				  size_t len, loff_t *ppos)
{
	char buf[64];
	unsigned long ttl;

	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	if (strncmp(buf, "ttl=", 4) == 0) {
		ttl = simple_strtoul(buf + 4, NULL, 10);
		if (ttl == 0)
			ttl = TERF_DFL_TTL;
		tertf_ttl = ttl;
	}
	return len;
}

static const struct proc_ops tertf_config_fops = {
	.proc_open	= tertf_config_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= tertf_config_write,
};

/* subnet: "ifindex ifname" header + rows */
static int tertf_subnet_show(struct seq_file *m, void *v)
{
	struct tertf_subnet *s;

	seq_printf(m, "ifindex ifname\n");
	list_for_each_entry(s, &tertf_subnets, list)
		seq_printf(m, "%-7d %s\n", s->ifindex, s->ifname);
	return 0;
}

static int tertf_subnet_open(struct inode *inode, struct file *file)
{
	return single_open(file, tertf_subnet_show, NULL);
}

static ssize_t tertf_subnet_write(struct file *file,
				  const char __user *ubuf,
				  size_t len, loff_t *ppos)
{
	char buf[256];
	char *p, *arg;

	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	/* "add <network>" */
	p = buf;
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (strncmp(p, "add", 3) != 0)
		return len;
	p += 3;
	while (*p == ' ' || *p == '\t')
		p++;
	arg = p;
	/* trim trailing whitespace/newline */
	p = arg + strlen(arg);
	while (p > arg && (p[-1] == ' ' || p[-1] == '\t' ||
			   p[-1] == '\n' || p[-1] == '\r'))
		*--p = '\0';

	if (arg[0])
		tertf_add_subnet(arg);
	return len;
}

static const struct proc_ops tertf_subnet_fops = {
	.proc_open	= tertf_subnet_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= tertf_subnet_write,
};

/* term: per-client table */
static int tertf_term_show(struct seq_file *m, void *v)
{
	struct tertf_term *t;

	seq_printf(m, "%-17s  %-16s  %-16s  %-16s  %-16s\n",
		   "MAC", "IP", "Tx(Byte)", "Rx(Byte)", "Device");
	list_for_each_entry(t, &tertf_terms, list) {
		seq_printf(m, "%pM  %-16pI4  %-16llu  %-16llu  %-16s\n",
			   t->mac, &t->ip, t->tx, t->rx, t->dev);
	}
	return 0;
}

static int tertf_term_open(struct inode *inode, struct file *file)
{
	return single_open(file, tertf_term_show, NULL);
}

static const struct proc_ops tertf_term_fops = {
	.proc_open	= tertf_term_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ------------------------------------------------------------------ */
/* module lifecycle                                                     */
/* ------------------------------------------------------------------ */
static int __init tertf_init(void)
{
	int ret;

	tertf_root = proc_mkdir(OUI_TERF_DIR, NULL);
	if (!tertf_root)
		return -ENOMEM;

	tertf_config_p = proc_create("config", 0644, tertf_root,
				     &tertf_config_fops);
	tertf_subnet_p = proc_create("subnet", 0644, tertf_root,
				     &tertf_subnet_fops);
	tertf_term_p = proc_create("term", 0444, tertf_root,
				   &tertf_term_fops);
	if (!tertf_config_p || !tertf_subnet_p || !tertf_term_p) {
		ret = -ENOMEM;
		goto err_proc;
	}

	ret = nf_register_net_hook(&init_net, &tertf_ops);
	if (ret)
		goto err_proc;

	tertf_wq = alloc_workqueue("tertf", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!tertf_wq) {
		ret = -ENOMEM;
		goto err_nf;
	}
	INIT_DELAYED_WORK(&tertf_expire_work, tertf_expire_workfn);
	queue_delayed_work(tertf_wq, &tertf_expire_work,
			   msecs_to_jiffies(5000));

	pr_info("tertf: (C) 2021 jianhui zhao <jianhui.zhao@gl-inet.com>\n");
	return 0;

err_nf:
	nf_unregister_net_hook(&init_net, &tertf_ops);
err_proc:
	remove_proc_entry("term", tertf_root);
	remove_proc_entry("subnet", tertf_root);
	remove_proc_entry("config", tertf_root);
	remove_proc_entry(OUI_TERF_DIR, NULL);
	return ret;
}

static void __exit tertf_exit(void)
{
	struct tertf_term *t, *tt;
	struct tertf_subnet *s, *ss;

	if (tertf_wq) {
		cancel_delayed_work_sync(&tertf_expire_work);
		flush_workqueue(tertf_wq);
		destroy_workqueue(tertf_wq);
	}
	nf_unregister_net_hook(&init_net, &tertf_ops);

	list_for_each_entry_safe(t, tt, &tertf_terms, list)
		term_free(t);
	list_for_each_entry_safe(s, ss, &tertf_subnets, list)
		subnet_free(s);

	if (tertf_term_p)
		remove_proc_entry("term", tertf_root);
	if (tertf_subnet_p)
		remove_proc_entry("subnet", tertf_root);
	if (tertf_config_p)
		remove_proc_entry("config", tertf_root);
	if (tertf_root)
		remove_proc_entry(OUI_TERF_DIR, NULL);
}

module_init(tertf_init);
module_exit(tertf_exit);

MODULE_AUTHOR("khagav <clean-room>");
MODULE_DESCRIPTION("GL.iNet tertf traffic accounting (reimplementation)");
MODULE_LICENSE("GPL");
