/*
 * gl-sdk4-hw-info.c
 *
 * GL.iNet hardware info module (clean-room reimplementation).
 *
 * Reverse-engineered from the original gl-sdk4-hw-info.ko shipped in
 * GL.iNet GL-MT1300 firmware (OpenWrt 22.03.4, kernel 5.10.176).
 *
 * Behavior (verified against the running device):
 *   - Creates /proc/gl-hw-info/ directory.
 *   - Reads the device-tree node "gl_hw" (compatible "gl-hw-info").
 *   - For each string property (model, lan, wan, radio, reset-button,
 *     switch-button, usb-port, usb3-bus-dev) creates a proc file that
 *     returns the property value.
 *   - For the "flash_size" u32 property creates a proc file returning
 *     "N MiB".
 *   - For each property of the "factory_data" child node (e.g.
 *     "device_mac = factory 0x4000") creates a proc file that reads
 *     the named MTD partition at the given offset and returns the value.
 *     MAC is formatted as xx:xx:xx:xx:xx:xx; everything else is a
 *     NUL-terminated string.
 *
 * The original also had optional /dev/mmc support (blkdev_get_by_path)
 * for models that store factory data on eMMC; MT1300 has no /dev/mmc so
 * that path is a no-op here but kept for completeness.
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
#include <linux/of.h>
#include <linux/etherdevice.h>
#include <linux/uaccess.h>
#include <linux/mtd/mtd.h>
#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/version.h>

#define GL_HW_DIR_NAME   "gl-hw-info"
#define GL_HW_DT_NODE    "gl_hw"
#define GL_HW_COMPAT     "gl-hw-info"

/* Entry types */
enum {
	GL_HW_STRING = 0,	/* fixed string from DT */
	GL_HW_U32,		/* u32 from DT, printed as "N MiB" */
	GL_HW_FACTORY,		/* read MTD partition at offset */
	GL_HW_MAC,		/* read 6 bytes, print xx:xx:xx:xx:xx:xx */
};

struct gl_hw_file {
	struct list_head list;
	char name[32];
	int type;
	/* GL_HW_STRING */
	char str_val[256];
	/* GL_HW_U32 */
	u32 u32_val;
	/* GL_HW_FACTORY / GL_HW_MAC */
	char mtd_name[32];
	unsigned long offset;
};

static struct proc_dir_entry *gl_hw_root;
static LIST_HEAD(gl_hw_files);
static struct mtd_info *gl_factory_mtd;	/* cached, optional */

/* ------------------------------------------------------------------ */
/* MTD factory read                                                     */
/* ------------------------------------------------------------------ */
static int gl_hw_read_factory(const char *mtd_name, unsigned long off,
			      char *buf, size_t len, size_t *retlen)
{
	struct mtd_info *mtd = NULL;
	size_t rlen = 0;
	int ret = -ENODEV;

	if (mtd_name && mtd_name[0])
		mtd = get_mtd_device_nm(mtd_name);
	if (IS_ERR_OR_NULL(mtd))
		mtd = gl_factory_mtd;
	if (IS_ERR_OR_NULL(mtd))
		return ret;

	if (len > 0 && off + len <= mtd->size) {
		ret = mtd_read(mtd, off, len, &rlen, buf);
		if (ret)
			ret = -EIO;
	}
	put_mtd_device(mtd);
	if (retlen)
		*retlen = rlen;
	return ret;
}

/* ------------------------------------------------------------------ */
/* proc file show                                                       */
/* ------------------------------------------------------------------ */
static int gl_hw_proc_show(struct seq_file *m, void *v)
{
	struct gl_hw_file *f = m->private;
	char buf[256];
	size_t rlen = 0;
	int ret;

	if (!f)
		return 0;

	switch (f->type) {
	case GL_HW_STRING:
		seq_printf(m, "%s", f->str_val);
		break;
	case GL_HW_U32:
		seq_printf(m, "%u MiB", f->u32_val >> 20);
		break;
	case GL_HW_MAC:
		memset(buf, 0, sizeof(buf));
		ret = gl_hw_read_factory(f->mtd_name, f->offset, buf, 6, &rlen);
		if (!ret && rlen >= 6)
			seq_printf(m, "%02x:%02x:%02x:%02x:%02x:%02x",
				   (u8)buf[0], (u8)buf[1], (u8)buf[2],
				   (u8)buf[3], (u8)buf[4], (u8)buf[5]);
		break;
	case GL_HW_FACTORY:
	default:
		memset(buf, 0, sizeof(buf));
		ret = gl_hw_read_factory(f->mtd_name, f->offset,
					 buf, sizeof(buf) - 1, &rlen);
		if (!ret && rlen) {
			buf[rlen] = '\0';
			seq_printf(m, "%s", buf);
		}
		break;
	}
	return 0;
}

static int gl_hw_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, gl_hw_proc_show, inode->i_private);
}

static const struct proc_ops gl_hw_fops = {
	.proc_open	= gl_hw_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */
static struct gl_hw_file *gl_hw_alloc(const char *name, int type)
{
	struct gl_hw_file *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;
	strscpy(f->name, name, sizeof(f->name));
	f->type = type;
	list_add_tail(&f->list, &gl_hw_files);
	return f;
}

/* Parse a "factory 0x4000" style property value. */
static int gl_hw_parse_factory(const char *val, char *mtd_name,
			       size_t mtd_len, unsigned long *off)
{
	char *p, *s;
	unsigned long o;
	char buf[64];

	if (!val || !mtd_name)
		return -EINVAL;
	strscpy(buf, val, sizeof(buf));

	p = buf;
	/* skip whitespace */
	while (*p == ' ' || *p == '\t')
		p++;
	/* mtd name: up to first space */
	s = p;
	while (*p && *p != ' ' && *p != '\t')
		p++;
	if (p == s)
		return -EINVAL;
	strscpy(mtd_name, s, mtd_len);
	mtd_name[mtd_len - 1] = '\0';
	if (*p)
		*p++ = '\0';
	/* skip whitespace */
	while (*p == ' ' || *p == '\t')
		p++;
	/* offset: hex (0x...) or decimal */
	o = simple_strtoul(p, NULL, 0);
	*off = o;
	return 0;
}

static void gl_hw_create_proc(struct gl_hw_file *f)
{
	proc_create_data(f->name, 0444, gl_hw_root, &gl_hw_fops, f);
}

/* ------------------------------------------------------------------ */
/* DT-driven creation                                                   */
/* ------------------------------------------------------------------ */
static void gl_hw_init_from_dt(void)
{
	struct device_node *np, *fnp;
	struct property *prop;
	const char *str;
	u32 u32v;
	char mtd_name[32];
	unsigned long off;
	struct gl_hw_file *f;

	np = of_find_node_by_name(NULL, GL_HW_DT_NODE);
	if (!np)
		np = of_find_compatible_node(NULL, NULL, GL_HW_COMPAT);
	if (!np)
		return;

	/* Direct string properties (model, lan, wan, radio, buttons...) */
	for_each_property_of_node(np, prop) {
		const char *pname = prop->name;

		if (!pname || !pname[0])
			continue;
		/* skip infrastructure props */
		if (!strcmp(pname, "name") ||
		    !strcmp(pname, "compatible") ||
		    !strcmp(pname, "#address-cells") ||
		    !strcmp(pname, "#size-cells") ||
		    !strcmp(pname, "reg") ||
		    !strcmp(pname, "factory_data") ||
		    !strcmp(pname, "status"))
			continue;

		/* flash_size: u32 -> "N MiB" */
		if (!strcmp(pname, "flash_size")) {
			if (!of_property_read_u32(np, pname, &u32v)) {
				f = gl_hw_alloc(pname, GL_HW_U32);
				if (f) {
					f->u32_val = u32v;
					gl_hw_create_proc(f);
				}
			}
			continue;
		}

		/* string property */
		if (!of_property_read_string(np, pname, &str)) {
			f = gl_hw_alloc(pname, GL_HW_STRING);
			if (f) {
				strscpy(f->str_val, str,
					sizeof(f->str_val));
				gl_hw_create_proc(f);
			}
		}
	}

	/* factory_data child node */
	fnp = of_get_child_by_name(np, "factory_data");
	if (fnp) {
		for_each_property_of_node(fnp, prop) {
			const char *pname = prop->name;

			if (!pname || !pname[0])
				continue;
			if (!strcmp(pname, "name") ||
			    !strcmp(pname, "compatible") ||
			    !strcmp(pname, "status"))
				continue;

			if (of_property_read_string(fnp, pname, &str))
				continue;

			if (gl_hw_parse_factory(str, mtd_name,
						sizeof(mtd_name), &off))
				continue;

			/* MAC is 6 raw bytes, everything else string */
			f = gl_hw_alloc(pname,
					!strcmp(pname, "device_mac") ?
					GL_HW_MAC : GL_HW_FACTORY);
			if (f) {
				strscpy(f->mtd_name, mtd_name,
					sizeof(f->mtd_name));
				f->offset = off;
				gl_hw_create_proc(f);
			}
		}
		of_node_put(fnp);
	}
	of_node_put(np);
}

/* ------------------------------------------------------------------ */
/* module lifecycle                                                     */
/* ------------------------------------------------------------------ */
static int __init gl_hw_info_init(void)
{
	gl_hw_root = proc_mkdir(GL_HW_DIR_NAME, NULL);
	if (!gl_hw_root)
		return -ENOMEM;

	/* cache factory MTD if present (best effort) */
	gl_factory_mtd = get_mtd_device_nm("factory");
	if (IS_ERR(gl_factory_mtd))
		gl_factory_mtd = NULL;

	gl_hw_init_from_dt();
	return 0;
}

static void __exit gl_hw_info_exit(void)
{
	struct gl_hw_file *f, *tmp;

	list_for_each_entry_safe(f, tmp, &gl_hw_files, list) {
		remove_proc_entry(f->name, gl_hw_root);
		list_del(&f->list);
		kfree(f);
	}
	if (gl_hw_root)
		remove_proc_entry(GL_HW_DIR_NAME, NULL);
	if (gl_factory_mtd)
		put_mtd_device(gl_factory_mtd);
}

module_init(gl_hw_info_init);
module_exit(gl_hw_info_exit);

MODULE_AUTHOR("khagav <clean-room>");
MODULE_DESCRIPTION("GL.iNet hardware info (reimplementation)");
MODULE_LICENSE("GPL");
