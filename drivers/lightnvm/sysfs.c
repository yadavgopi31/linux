#include <linux/kernel.h>
#include <linux/lightnvm.h>
#include <linux/miscdevice.h>
#include <linux/kobject.h>
#include <linux/blk-mq.h>

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
 * Functions and data structures for exposing LightNVM enabled devices.
 */

static ssize_t nvm_dev_attr_show(struct device *dev,
				 struct device_attribute *dattr, char *page)
{
	struct nvm_dev *ndev = container_of(dev, struct nvm_dev, dev);
	struct nvm_id *id = &ndev->identity;
	struct nvm_id_group *grp = &id->groups[0];
	struct attribute *attr = &dattr->attr;

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
		if (!ndev->mt)
			return scnprintf(page, PAGE_SIZE, "%s\n", "none");
		return scnprintf(page, PAGE_SIZE, "%s\n", ndev->mt->name);
	} else if (strcmp(attr->name, "ppa_format") == 0) {
		return scnprintf(page, PAGE_SIZE,
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			id->ppaf.ch_offset, id->ppaf.ch_len,
			id->ppaf.lun_offset, id->ppaf.lun_len,
			id->ppaf.pln_offset, id->ppaf.pln_len,
			id->ppaf.blk_offset, id->ppaf.blk_len,
			id->ppaf.pg_offset, id->ppaf.pg_len,
			id->ppaf.sect_offset, id->ppaf.sect_len);
	} else if (strcmp(attr->name, "media_type") == 0) {	/* u8 */
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
		return scnprintf(page,
				 PAGE_SIZE,
				 "Unhandled attr(%s) in `nvm_dev_attr_show`\n",
				 attr->name);
	}
}

#define NVM_DEV_ATTR_RO(_name) 					\
static DEVICE_ATTR(_name, S_IRUGO, nvm_dev_attr_show, NULL);

NVM_DEV_ATTR_RO(version);
NVM_DEV_ATTR_RO(vendor_opcode);
NVM_DEV_ATTR_RO(num_groups);
NVM_DEV_ATTR_RO(capabilities);
NVM_DEV_ATTR_RO(device_mode);
NVM_DEV_ATTR_RO(ppa_format);
NVM_DEV_ATTR_RO(media_manager);

NVM_DEV_ATTR_RO(media_type);
NVM_DEV_ATTR_RO(flash_media_type);
NVM_DEV_ATTR_RO(num_channels);
NVM_DEV_ATTR_RO(num_luns);
NVM_DEV_ATTR_RO(num_planes);
NVM_DEV_ATTR_RO(num_blocks);
NVM_DEV_ATTR_RO(num_pages);
NVM_DEV_ATTR_RO(page_size);
NVM_DEV_ATTR_RO(hw_sector_size);
NVM_DEV_ATTR_RO(oob_sector_size);
NVM_DEV_ATTR_RO(read_typ);
NVM_DEV_ATTR_RO(read_max);
NVM_DEV_ATTR_RO(prog_typ);
NVM_DEV_ATTR_RO(prog_max);
NVM_DEV_ATTR_RO(erase_typ);
NVM_DEV_ATTR_RO(erase_max);
NVM_DEV_ATTR_RO(multiplane_modes);
NVM_DEV_ATTR_RO(media_capabilities);
NVM_DEV_ATTR_RO(channel_parallelism);

#define NVM_DEV_ATTR(_name) (dev_attr_##_name##)

static struct attribute *nvm_dev_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_vendor_opcode.attr,
	&dev_attr_num_groups.attr,
	&dev_attr_capabilities.attr,
	&dev_attr_device_mode.attr,
	&dev_attr_media_manager.attr,

	&dev_attr_ppa_format.attr,
	&dev_attr_media_type.attr,
	&dev_attr_flash_media_type.attr,
	&dev_attr_num_channels.attr,
	&dev_attr_num_luns.attr,
	&dev_attr_num_planes.attr,
	&dev_attr_num_blocks.attr,
	&dev_attr_num_pages.attr,
	&dev_attr_page_size.attr,
	&dev_attr_hw_sector_size.attr,
	&dev_attr_oob_sector_size.attr,
	&dev_attr_read_typ.attr,
	&dev_attr_read_max.attr,
	&dev_attr_prog_typ.attr,
	&dev_attr_prog_max.attr,
	&dev_attr_erase_typ.attr,
	&dev_attr_erase_max.attr,
	&dev_attr_multiplane_modes.attr,
	&dev_attr_media_capabilities.attr,
	&dev_attr_channel_parallelism.attr,
	NULL,
};

static struct attribute_group nvm_dev_attr_group = {
	.name = "lightnvm",
	.attrs = nvm_dev_attrs,
};


const static struct attribute_group *nvm_dev_attr_groups[] = {
	&nvm_dev_attr_group,
	NULL,
};

static void nvm_dev_release(struct device *dev)
{
	struct nvm_dev *ndev = container_of(dev, struct nvm_dev, dev);

	pr_debug("nvm/sysfs: `nvm_dev_release`\n");

	kfree(ndev);
}

static struct class *nvm_class;

static struct device_type nvm_type = {
	.name		= "lightnvm",
	.groups		= nvm_dev_attr_groups,
	.release	= nvm_dev_release,
};

int nvm_sysfs_register_dev(struct nvm_dev *dev)
{
	dev->dev.parent = dev->parent_dev;
	dev_set_name(&dev->dev, "%s", dev->name);
	dev->dev.class = dev->parent_dev->class;
	dev->dev.type = &nvm_type;
	device_initialize(&dev->dev);
	device_add(&dev->dev);

	blk_mq_register_dev(&dev->dev, dev->q);

	return 0;
}

void nvm_sysfs_unregister_dev(struct nvm_dev *dev)
{

}

int nvm_sysfs_register(struct miscdevice *miscdev)
{
	nvm_class = class_create(THIS_MODULE, "lightnvm");
	if (IS_ERR(nvm_class))
		return -EINVAL;

	targets = kset_create_and_add("targets", NULL,
			kobject_get(&miscdev->this_device->kobj));
	if (!targets) {
		kobject_put(&miscdev->this_device->kobj);
		class_destroy(nvm_class);
		return -ENOMEM;
	}

	return 0;
}

void nvm_sysfs_unregister(struct miscdevice *miscdev)
{
	kset_unregister(targets);
	class_destroy(nvm_class);
}
