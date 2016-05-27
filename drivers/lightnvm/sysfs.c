#include <linux/kernel.h>
#include <linux/lightnvm.h>
#include <linux/miscdevice.h>
#include <linux/kobject.h>

#include "sysfs.h"

static struct kset *targets;

/*
 * Functions and data structures for LightNVM targets in sysfs.
 * This file contains the show-functions, release-functions, default_attrs,
 * sysfs_register* function, and ktypes.
 */

#define NVM_TARGET_ATTR_RO(_name)					\
	static struct attribute nvm_target_##_name##_attr = {		\
	.name = __stringify(_name),					\
	.mode = S_IRUGO							\
	}

#define NVM_TARGET_ATTR_LIST(_name) (&nvm_target_##_name##_attr)

NVM_TARGET_ATTR_RO(type);

static struct attribute *nvm_target_default_attrs[] = {
	NVM_TARGET_ATTR_LIST(type),
	NULL,
};

static ssize_t nvm_target_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct nvm_target *target = container_of(kobj, struct nvm_target, kobj);

	if (strcmp(attr->name, "type") == 0) {
		return scnprintf(page, PAGE_SIZE, "%s\n",
				 target->type->name);
	} else {
		return scnprintf(page, PAGE_SIZE,
			"Unhandled attr(%s) in `nvm_target_attr_show`\n",
			attr->name);
	}
}

static const struct sysfs_ops target_sysfs_ops = {
	.show = nvm_target_attr_show,
};

static void nvm_target_release(struct kobject *kobj)
{
	struct nvm_target *tgt = container_of(kobj, struct nvm_target, kobj);

	pr_debug("nvm/sysfs: `nvm_target_release`\n");

	kfree(tgt);
}

static struct kobj_type nvm_target_ktype = {
	.sysfs_ops	= &target_sysfs_ops,
	.default_attrs	= nvm_target_default_attrs,
	.release	= nvm_target_release
};

void nvm_sysfs_unregister_target(struct nvm_target *target)
{
	kobject_del(&target->kobj);
	kobject_put(&target->kobj);
}

int nvm_sysfs_register_target(struct nvm_target *target)
{
	int ret;

	target->kobj.kset = targets;
	ret = kobject_init_and_add(&target->kobj, &nvm_target_ktype, NULL, "%s",
				   target->disk->disk_name);
	if (ret < 0) {
		pr_err("nvm/sysfs: `_register_target` failed.\n");
		kobject_put(&target->kobj);
		return ret;
	}

	kobject_uevent(&target->kobj, KOBJ_ADD);

	return 0;
}

/*
 * Functions and data structures for exposing
 * group-information of LightNVM enabled devices.
 *
 * NOTE: these are internal to sysfs.c and used by `nvm_sysfs_[un]register_dev`.
 */

static void nvm_grp_release(struct kobject *kobj)
{
	pr_debug("nvm/sysfs: called `nvm_grp_release`.\n");

	/* This does nothing since `nvm_id_group` information is embedded inside
	 * `nvm_dev`. Management of `nvm_id_group` is therefore handled by the
	 * release of `nvm_dev_release`.
	 */
}

#define NVM_GRP_ATTR_RO(_name)						\
	static struct attribute nvm_grp_##_name##_attr = {		\
	.name = __stringify(_name),					\
	.mode = S_IRUGO							\
	}

#define NVM_GRP_ATTR_LIST(_name) (&nvm_grp_##_name##_attr)

NVM_GRP_ATTR_RO(media_type);
NVM_GRP_ATTR_RO(flash_media_type);
NVM_GRP_ATTR_RO(num_channels);
NVM_GRP_ATTR_RO(num_luns);
NVM_GRP_ATTR_RO(num_planes);
NVM_GRP_ATTR_RO(num_blocks);
NVM_GRP_ATTR_RO(num_pages);
NVM_GRP_ATTR_RO(page_size);
NVM_GRP_ATTR_RO(hw_sector_size);
NVM_GRP_ATTR_RO(oob_sector_size);
NVM_GRP_ATTR_RO(read_typ);
NVM_GRP_ATTR_RO(read_max);
NVM_GRP_ATTR_RO(prog_typ);
NVM_GRP_ATTR_RO(prog_max);
NVM_GRP_ATTR_RO(erase_typ);
NVM_GRP_ATTR_RO(erase_max);
NVM_GRP_ATTR_RO(multiplane_modes);
NVM_GRP_ATTR_RO(media_capabilities);
NVM_GRP_ATTR_RO(channel_parallelism);

static struct attribute *nvm_grp_default_attrs[] = {
	NVM_GRP_ATTR_LIST(media_type),
	NVM_GRP_ATTR_LIST(flash_media_type),
	NVM_GRP_ATTR_LIST(num_channels),
	NVM_GRP_ATTR_LIST(num_luns),
	NVM_GRP_ATTR_LIST(num_planes),
	NVM_GRP_ATTR_LIST(num_blocks),
	NVM_GRP_ATTR_LIST(num_pages),
	NVM_GRP_ATTR_LIST(page_size),
	NVM_GRP_ATTR_LIST(hw_sector_size),
	NVM_GRP_ATTR_LIST(oob_sector_size),
	NVM_GRP_ATTR_LIST(read_typ),
	NVM_GRP_ATTR_LIST(read_max),
	NVM_GRP_ATTR_LIST(prog_typ),
	NVM_GRP_ATTR_LIST(prog_max),
	NVM_GRP_ATTR_LIST(erase_typ),
	NVM_GRP_ATTR_LIST(erase_max),
	NVM_GRP_ATTR_LIST(multiplane_modes),
	NVM_GRP_ATTR_LIST(media_capabilities),
	NVM_GRP_ATTR_LIST(channel_parallelism),
	NULL,
};

static ssize_t nvm_grp_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *page)
{
	struct nvm_id_group *grp = container_of(kobj, struct nvm_id_group,
						kobj);

	if (strcmp(attr->name, "media_type") == 0) {		/* u8 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->mtype);
	} else if (strcmp(attr->name, "flash_media_type") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->fmtype);
	} else if (strcmp(attr->name, "num_channels") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_ch);
	} else if (strcmp(attr->name, "num_luns") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_lun);
	} else if (strcmp(attr->name, "num_planes") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_pln);
	} else if (strcmp(attr->name, "num_blocks") == 0) {	/* u16 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_blk);
	} else if (strcmp(attr->name, "num_pages") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_pg);
	} else if (strcmp(attr->name, "page_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->fpg_sz);
	} else if (strcmp(attr->name, "hw_sector_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->csecs);
	} else if (strcmp(attr->name, "oob_sector_size") == 0) {/* u32 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->sos);
	} else if (strcmp(attr->name, "read_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->trdt);
	} else if (strcmp(attr->name, "read_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->trdm);
	} else if (strcmp(attr->name, "prog_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tprt);
	} else if (strcmp(attr->name, "prog_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tprm);
	} else if (strcmp(attr->name, "erase_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tbet);
	} else if (strcmp(attr->name, "erase_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tbem);
	} else if (strcmp(attr->name, "multiplane_modes") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", grp->mpos);
	} else if (strcmp(attr->name, "media_capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", grp->mccap);
	} else if (strcmp(attr->name, "channel_parallelism") == 0) {/* u16 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->cpar);
	} else {
		return scnprintf(page, PAGE_SIZE,
				 "Unhandled attr(%s) in `nvm_grp_attr_show`\n",
				 attr->name);
	}
}

static const struct sysfs_ops nvm_grp_sysfs_ops = {
	.show	= nvm_grp_attr_show,
};

static struct kobj_type nvm_grp_ktype = {
	.sysfs_ops	= &nvm_grp_sysfs_ops,
	.default_attrs	= nvm_grp_default_attrs,
	.release	= nvm_grp_release
};

void nvm_sysfs_unregister_grps(struct nvm_dev *dev)
{
	int i;

	for (i = 0; i < dev->identity.cgrps; i++) {
		kobject_del(&dev->identity.groups[i].kobj);
		kobject_put(&dev->identity.groups[i].kobj);
		kobject_put(&dev->kobj);
	}
}

static int nvm_sysfs_register_grps(struct nvm_dev *dev)
{
	int i, ret;

	for (i = 0; i < dev->identity.cgrps; i++) {
		ret = kobject_init_and_add(&dev->identity.groups[i].kobj,
					   &nvm_grp_ktype,
					   kobject_get(&dev->kobj),
					   "grp%u", i);
		if (ret < 0) {
			pr_err("nvm/sysfs: `_register_grps` failed(%d)\n", ret);
			goto grps_error;
		}

		kobject_uevent(&dev->identity.groups[i].kobj, KOBJ_ADD);
	}

	return 0;

grps_error:
	kobject_put(&dev->identity.groups[i].kobj);	/* The failed grp*/
	kobject_put(&dev->kobj);

	for (i = i - 1; i > 0; i--) {			/* Successful grps */
		kobject_del(&dev->identity.groups[i].kobj);
		kobject_put(&dev->identity.groups[i].kobj);
		kobject_put(&dev->kobj);
	}

	return ret;
}

/*
 * Functions and data structures for exposing LightNVM enabled devices.
 */

#define NVM_DEV_ATTR_RO(_name)						\
	static struct attribute nvm_dev_##_name##_attr = {		\
	.name = __stringify(_name),					\
	.mode = S_IRUGO							\
	}

#define NVM_DEV_ATTR_LIST(_name) (&nvm_dev_##_name##_attr)

NVM_DEV_ATTR_RO(version);
NVM_DEV_ATTR_RO(vendor_opcode);
NVM_DEV_ATTR_RO(num_groups);
NVM_DEV_ATTR_RO(capabilities);
NVM_DEV_ATTR_RO(device_mode);
NVM_DEV_ATTR_RO(ppa_format);
NVM_DEV_ATTR_RO(media_manager);

static struct attribute *nvm_dev_default_attrs[] = {
	NVM_DEV_ATTR_LIST(version),
	NVM_DEV_ATTR_LIST(vendor_opcode),
	NVM_DEV_ATTR_LIST(num_groups),
	NVM_DEV_ATTR_LIST(capabilities),
	NVM_DEV_ATTR_LIST(device_mode),
	NVM_DEV_ATTR_LIST(ppa_format),
	NVM_DEV_ATTR_LIST(media_manager),
	NULL,
};

static ssize_t nvm_dev_attr_show(struct kobject *kobj, struct attribute *attr,
				char *page)
{
	struct nvm_dev *dev = container_of(kobj, struct nvm_dev, kobj);
	struct nvm_id *id = &dev->identity;

	if (strcmp(attr->name, "version") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->ver_id);
	} else if (strcmp(attr->name, "vendor_opcode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->vmnt);
	} else if (strcmp(attr->name, "num_groups") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->cgrps);
	} else if (strcmp(attr->name, "capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->cap);
	} else if (strcmp(attr->name, "device_mode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->dom);
	} else if (strcmp(attr->name, "media_manager") == 0) {
		if (!dev->mt)
			return scnprintf(page, PAGE_SIZE, "%s\n", "none");
		return scnprintf(page, PAGE_SIZE, "%s\n", dev->mt->name);
	} else if (strcmp(attr->name, "ppa_format") == 0) {
		return scnprintf(page, PAGE_SIZE,
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			id->ppaf.ch_offset, id->ppaf.ch_len,
			id->ppaf.lun_offset, id->ppaf.lun_len,
			id->ppaf.pln_offset, id->ppaf.pln_len,
			id->ppaf.blk_offset, id->ppaf.blk_len,
			id->ppaf.pg_offset, id->ppaf.pg_len,
			id->ppaf.sect_offset, id->ppaf.sect_len);
	} else {
		return scnprintf(page,
				 PAGE_SIZE,
				 "Unhandled attr(%s) in `nvm_dev_attr_show`\n",
				 attr->name);
	}
}

static const struct sysfs_ops nvm_dev_sysfs_ops = {
	.show	= nvm_dev_attr_show,
};

static void nvm_dev_release(struct kobject *kobj)
{
	struct nvm_dev *dev = container_of(kobj, struct nvm_dev, kobj);

	pr_debug("nvm/sysfs: `nvm_dev_release`\n");

	kfree(dev);
}

static struct kobj_type nvm_dev_ktype = {
	.sysfs_ops	= &nvm_dev_sysfs_ops,
	.default_attrs	= nvm_dev_default_attrs,
	.release	= nvm_dev_release
};

void nvm_sysfs_unregister_dev(struct nvm_dev *dev)
{
	nvm_sysfs_unregister_grps(dev);

	kobject_del(&dev->kobj);
	kobject_put(&dev->kobj);
}

static void nvm_release(struct device *dev)
{
/* fill in */
}

struct class nvm_class = {
	.name		= "lightnvm",
};

static const struct attribute_group *nvm_attr_groups[] = {
	NULL
};

static struct device_type nvm_type = {
	.name		= "nvm",
	.groups		= nvm_attr_groups,
	.release	= nvm_release,
};

int nvm_sysfs_register_dev(struct nvm_dev *dev)
{
	int ret;

	dev->dev.parent = dev->parent_dev;
	dev_set_name(&dev->dev, "%s", dev->name);
	dev->dev.class = &nvm_class;
	dev->dev.type = &nvm_type;
	device_initialize(&dev->dev);
	device_add(&dev->dev);

	ret = kobject_init_and_add(&dev->dev.kobj, &nvm_dev_ktype, NULL, "%s",
				   dev->name);
	if (ret < 0) {
		pr_err("nvm/sysfs: `_register_dev` failed(%d).\n", ret);
		kobject_put(&dev->kobj);
		return ret;
	}
	kobject_uevent(&dev->kobj, KOBJ_ADD);

	ret = nvm_sysfs_register_grps(dev);
	if (ret < 0) {
		pr_err("nvm/sysfs: `_register_dev` rolling back.");

		kobject_del(&dev->kobj);
		kobject_put(&dev->kobj);

		return ret;
	}

	return 0;
}

/*
 * Functions for exposing LightNVM devices and targets in sysfs.
 *
 * They will reside as children of the given `miscdevice`.
 */

int nvm_sysfs_register(struct miscdevice *miscdev)
{
	targets = kset_create_and_add("targets", NULL,
			kobject_get(&miscdev->this_device->kobj));
	if (!targets) {
		kobject_put(&miscdev->this_device->kobj);
		return -ENOMEM;
	}

	return 0;
}

void nvm_sysfs_unregister(struct miscdevice *miscdev)
{
	kset_unregister(targets);
}
