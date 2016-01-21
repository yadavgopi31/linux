/*
 * Copyright (C) 2015 IT University of Copenhagen. All rights reserved.
 * Initial release: Matias Bjorling <m@bjorling.me>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/sem.h>
#include <linux/bitmap.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/lightnvm.h>
#include <linux/sched/sysctl.h>
#include <uapi/linux/lightnvm.h>

static LIST_HEAD(nvm_targets);
static LIST_HEAD(nvm_mgrs);
static LIST_HEAD(nvm_devices);
static DECLARE_RWSEM(nvm_lock);

static struct nvm_tgt_type *nvm_find_target_type(const char *name)
{
	struct nvm_tgt_type *tt;

	list_for_each_entry(tt, &nvm_targets, list)
		if (!strcmp(name, tt->name))
			return tt;

	return NULL;
}

/**
 * nvm_register_target - Register a target with the LightNVM subsystem
 * @tt:    Populated &struct nvm_tgt_type structure
 *
 * Description:
 *   nvm_register_target() registers a target with the LightNVM subsystem. It
 *   can then later be instantiated by the media manager. If target is already
 *   registered, it will return -EEXIST.
 *
 *   Return <0 on error, 0 on success.
 **/
int nvm_register_target(struct nvm_tgt_type *tt)
{
	int ret = 0;

	down_write(&nvm_lock);
	if (nvm_find_target_type(tt->name))
		ret = -EEXIST;
	else
		list_add(&tt->list, &nvm_targets);
	up_write(&nvm_lock);

	return ret;
}
EXPORT_SYMBOL(nvm_register_target);

/**
 * nvm_unregister_target - Unregister a target with the LightNVM subsystem
 * @tt:    Populated &struct nvm_tgt_type structure
 *
 * Description:
 *   nvm_unregister_target() unregisters a target from the LightNVM subsystem.
 *   On unregistration, it assumes the target has no instances left.
 **/
void nvm_unregister_target(struct nvm_tgt_type *tt)
{
	if (!tt)
		return;

	down_write(&nvm_lock);
	list_del(&tt->list);
	up_write(&nvm_lock);
}
EXPORT_SYMBOL(nvm_unregister_target);

/**
 * nvm_dev_dma_alloc - Allocated device DMA-able memory
 * @dev:         The &struct nvm_dev in question
 * @mem_flags:   Memory flags passed for allocation
 * @dma_handler: DMA handler associated to the allocation
 *
 * Description:
 *  nvm_dev_dma_alloc() calls the device driver specific DMA allocator. Each
 *  device driver may implement their own method to retrieve DMA memory and thus
 *  this allows the allocation to reuse internal pools used by device driver.
 *
 *  Returns pointer to the data buffer allocated.
 **/
void *nvm_dev_dma_alloc(struct nvm_dev *dev, gfp_t mem_flags,
							dma_addr_t *dma_handler)
{
	return dev->ops->dev_dma_alloc(dev, dev->ppalist_pool, mem_flags,
								dma_handler);
}
EXPORT_SYMBOL(nvm_dev_dma_alloc);

/**
 * nvm_dev_dma_free - Frees device DMA-able memory
 * @dev:         The &struct nvm_dev in question
 * @ptr:         Pointer to data buffer allocated by nvm_dev_dma_alloc
 * @dma_handler: DMA handler associated to the allocation
 *
 * Description:
 *  nvm_dev_dma_free() calls the device driver specific DMA free. Each
 *  device driver may implement their own method to retrieve DMA memory and this
 *  allows it to free the memory again.
 **/
void nvm_dev_dma_free(struct nvm_dev *dev, void *ptr, dma_addr_t dma_handler)
{
	dev->ops->dev_dma_free(dev->ppalist_pool, ptr, dma_handler);
}
EXPORT_SYMBOL(nvm_dev_dma_free);

static struct nvmm_type *nvm_find_mgr_type(const char *name)
{
	struct nvmm_type *mt;

	list_for_each_entry(mt, &nvm_mgrs, list)
		if (!strcmp(name, mt->name))
			return mt;

	return NULL;
}

struct nvmm_type *nvm_init_mgr(struct nvm_dev *dev)
{
	struct nvmm_type *mt;
	int ret;

	lockdep_assert_held(&nvm_lock);

	list_for_each_entry(mt, &nvm_mgrs, list) {
		if (strncmp(dev->sb.mmtype, mt->name, NVM_MMTYPE_LEN))
			continue;

		ret = mt->register_mgr(dev);
		if (ret < 0) {
			pr_err("nvm: media mgr failed to init (%d) on dev %s\n",
								ret, dev->name);
			return NULL; /* initialization failed */
		} else if (ret > 0)
			return mt;
	}

	return NULL;
}

/**
 * nvm_register_mgr - Register media manager with LightNVM subsystem
 * @mt:    The &struct nvmm_type to register
 *
 * Description:
 *   nvm_register_mgr() searches for if the media manager already is and ensures
 *   that it is added to registered managers if not.
 *
 *   Returns <0 on error, 0 on success
 **/
int nvm_register_mgr(struct nvmm_type *mt)
{
	struct nvm_dev *dev;
	int ret = 0;

	down_write(&nvm_lock);
	if (nvm_find_mgr_type(mt->name)) {
		ret = -EEXIST;
		goto finish;
	} else {
		list_add(&mt->list, &nvm_mgrs);
	}

	/* try to register media mgr if any device have none configured */
	list_for_each_entry(dev, &nvm_devices, devices) {
		if (dev->mt)
			continue;

		dev->mt = nvm_init_mgr(dev);
	}
finish:
	up_write(&nvm_lock);

	return ret;
}
EXPORT_SYMBOL(nvm_register_mgr);

/**
 * nvm_unregister_mgr - Unregister a media manager from the LightNVM subsystem
 * @mt:    The &struct nvmm_type to unregister
 *
 * Description:
 *   nvm_unregister_mgr() will remove the manager. It assumes that all previous
 *   instances is removed.
 **/
void nvm_unregister_mgr(struct nvmm_type *mt)
{
	if (!mt)
		return;

	down_write(&nvm_lock);
	list_del(&mt->list);
	up_write(&nvm_lock);
}
EXPORT_SYMBOL(nvm_unregister_mgr);

static struct nvm_dev *nvm_find_nvm_dev(const char *name)
{
	struct nvm_dev *dev;

	list_for_each_entry(dev, &nvm_devices, devices)
		if (!strcmp(name, dev->name))
			return dev;

	return NULL;
}

/**
 * nvm_get_blk_unlocked - Get free logical block from logical lun
 * @dev:    The @struct nvm_dev in question
 * @lun:    The logical lun to retrieve the logical block from
 * @flags:  Any flags to direct logical block selection
 *
 * Description:
 *   nvm_get_blk_unlocked() calls the media manager get_blk_unlocked, which in
 *   turn will get a free (if available) logical block from the logical lun. The
 *   flags parameter allows the user to pass flags to direct logical block
 *   selection.
 *
 *   nvm_lun lock must be held.
 *
 *   Returns the associated nvm_block structure, or NULL on error.
 **/
struct nvm_block *nvm_get_blk_unlocked(struct nvm_dev *dev, struct nvm_lun *lun,
							unsigned long flags)
{
	return dev->mt->get_blk_unlocked(dev, lun, flags);
}
EXPORT_SYMBOL(nvm_get_blk_unlocked);

/**
 * nvm_put_blk_unlocked - Put logical block to logical lun
 * @dev:    The @struct nvm_dev in question
 * @blk:    The logical block to return to the media manager
 *
 * Description:
 *   nvm_put_blk_unlocked() calls the media manager put_blk_unlocked, which in
 *   turn will return the logical block to the media manager. The media
 *   manager decides how to place it when returned and may take it out of
 *   service if necessary. All data within the logical block is assumed to be
 *   invalid. The caller must not access the nvm_block structure after
 *   completion.
 *
 *   nvm_lun lock must be held.
 **/
void nvm_put_blk_unlocked(struct nvm_dev *dev, struct nvm_block *blk)
{
	return dev->mt->put_blk_unlocked(dev, blk);
}
EXPORT_SYMBOL(nvm_put_blk_unlocked);

/**
 * nvm_get_blk - Get free logical block from logical lun
 * @dev:    The @struct nvm_dev in question
 * @lun:    The logical lun to retrieve the logical block from
 * @flags:  Any flags to direct logical block selection
 *
 * Description:
 *   nvm_get_blk() calls the media manager get_blk, which in turn will get a
 *   free (if available) logical block from the logical lun. The flags parameter
 *   allows the user to pass flags to direct logical block selection.
 *
 *   nvm_lun lock must _not_ be held.
 *
 *   Returns the select nvm_block, or NULL on error.
 **/
struct nvm_block *nvm_get_blk(struct nvm_dev *dev, struct nvm_lun *lun,
							unsigned long flags)
{
	return dev->mt->get_blk(dev, lun, flags);
}
EXPORT_SYMBOL(nvm_get_blk);

/**
 * nvm_put_blk - Put logical block to logical lun
 * @dev:    The @struct nvm_dev in question
 * @blk:    The logical block to return to the media manager
 *
 * Description:
 *   nvm_put_blk() calls the media manager put_blk, which in turn will return
 *   the logical block to the media manager. The media manager decides how to
 *   place it when returned and may take it out of service if necessary.
 *   All data within the logical block is assumed to be invalid. The caller must
 *   not access the nvm_block structure after completion.
 *
 *   nvm_lun lock must _not_ be held.
 **/
void nvm_put_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	return dev->mt->put_blk(dev, blk);
}
EXPORT_SYMBOL(nvm_put_blk);

/**
 * nvm_submit_io - Submit an io to the underlying media media manager
 * @dev:    The &struct nvm_dev in question
 * @rqd:    The &struct nvm_rq that describes the I/O to be submitted
 *
 * Description:
 *   nvm_submit_io() will submit the nvm_rq to the media manager. It is up to
 *   the media manager to direct the I/O to the underlying device. Any
 *   transformation of the rqd->ppalist structure is performed; It is the
 *   caller's responsibility that it is kept within device max_sect size.
 *
 *   Returns <0 on error, 0 on success
 **/
int nvm_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	return dev->mt->submit_io(dev, rqd);
}
EXPORT_SYMBOL(nvm_submit_io);

/**
 * nvm_erase_blk - Submit erase of the generic nvm_block
 * @dev:    The &struct nvm_dev in question
 * @blk:    The &nvm_block structure describing the block in the logical
 *          representation.
 *
 * Description:
 *   nvm_erase_blk() will submit the logical block to be erased by the media
 *   manager. It is the responsibility of the media manager to convert from the
 *   logical representation to the physical device representation and erase the
 *   appropriate block(s) that the nvm_block structure represents.
 *
 *   Returns <0 on error, 0 on success
 **/
int nvm_erase_blk(struct nvm_dev *dev, struct nvm_block *blk)
{
	return dev->mt->erase_blk(dev, blk, 0);
}
EXPORT_SYMBOL(nvm_erase_blk);

/**
 * nvm_addr_to_generic_mode - Convert from device-specific to generic addressing
 * @dev:    The &struct nvm_dev in question
 * @rqd:    The &struct nvm_rq request with device-specific addresses
 *
 * Description:
 * nvm_generic_to_addr_mode() transforms physical addresses from generic
 * addressing to device-specific addressing. Targets always work with generic
 * addresses, and devices always work with device-specific. It is the
 * responsibility of the media manager to convert to and from device-specific
 * addresses.
 **/
void nvm_addr_to_generic_mode(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	int i;

	if (rqd->nr_pages > 1) {
		for (i = 0; i < rqd->nr_pages; i++)
			rqd->ppa_list[i] = dev_to_generic_addr(dev,
							rqd->ppa_list[i]);
	} else {
		rqd->ppa_addr = dev_to_generic_addr(dev, rqd->ppa_addr);
	}
}
EXPORT_SYMBOL(nvm_addr_to_generic_mode);

/**
 * nvm_generic_to_addr_mode - Convert from generic to device-specific addressing
 * @dev:    The &struct nvm_dev in question
 * @rqd:    The &struct nvm_rq request with generic addresses
 *
 * Description:
 * nvm_generic_to_addr_mode() transforms physical addresses from generic
 * addressing to device-specific addressing. Targets always work with generic
 * addresses, and devices always work with device-specific. It is the
 * responsibility of the media manager to convert to and from device-specific
 * addresses.
 **/
void nvm_generic_to_addr_mode(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	int i;

	if (rqd->nr_pages > 1) {
		for (i = 0; i < rqd->nr_pages; i++)
			rqd->ppa_list[i] = generic_to_dev_addr(dev,
							rqd->ppa_list[i]);
	} else {
		rqd->ppa_addr = generic_to_dev_addr(dev, rqd->ppa_addr);
	}
}
EXPORT_SYMBOL(nvm_generic_to_addr_mode);

/**
 * nvm_set_rqd_ppalist - Set nvm_rqd with associated ppa list
 * @dev:    The &struct nvm_dev in question
 * @rqd:    The &struct nvm_rq to store the ppa list in
 * @ppas:   The &struct ppa_addr ppa list of addresses to store in rqd
 * @nr_ppas:The number of ppas in the ppa list
 *
 * Description:
 *   nvm_set_rqd_ppalist() transforms a ppa list to its nvm_rq counterpart.
 *   nvm_rq commands may be expanded into its single, dual, quad plane counter
 *   parts. This function expands takes care of this and passes it into the
 *   nvm_rq structure.
 *
 *   Return <0 on error, 0 on success
 **/
int nvm_set_rqd_ppalist(struct nvm_dev *dev, struct nvm_rq *rqd,
					struct ppa_addr *ppas, int nr_ppas)
{
	int i, plane_cnt, pl_idx;

	if (dev->plane_mode == NVM_PLANE_SINGLE && nr_ppas == 1) {
		rqd->nr_pages = 1;
		rqd->ppa_addr = ppas[0];

		return 0;
	}

	plane_cnt = (1 << dev->plane_mode);
	rqd->nr_pages = plane_cnt * nr_ppas;

	if (dev->ops->max_phys_sect < rqd->nr_pages)
		return -EINVAL;

	rqd->ppa_list = nvm_dev_dma_alloc(dev, GFP_KERNEL, &rqd->dma_ppa_list);
	if (!rqd->ppa_list) {
		pr_err("nvm: failed to allocate dma memory\n");
		return -ENOMEM;
	}

	for (pl_idx = 0; pl_idx < plane_cnt; pl_idx++) {
		for (i = 0; i < nr_ppas; i++) {
			ppas[i].g.pl = pl_idx;
			rqd->ppa_list[(pl_idx * nr_ppas) + i] = ppas[i];
		}
	}

	return 0;
}
EXPORT_SYMBOL(nvm_set_rqd_ppalist);

void nvm_free_rqd_ppalist(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	if (!rqd->ppa_list)
		return;

	nvm_dev_dma_free(dev, rqd->ppa_list, rqd->dma_ppa_list);
}
EXPORT_SYMBOL(nvm_free_rqd_ppalist);

/**
 * nvm_erase_ppa - Erase the block(s) associated with the physical addresses
 * @dev:     The @struct nvm_dev in question
 * @ppas:    Pointer to a list of PPAs to erase
 * @nr_ppas: Number of PPAs in ppas pointer
 *
 * Description:
 *   nvm_erase_ppa() erases the physical blocks corresponding to the ppas and
 *   number of physical addresses nr_ppas. It assumes the PPAs are in generic
 *   addressing format. On completion, the PPAs blocks will have been erased.
 *
 *   It is the responsibility of the user to not submit more ppas than device
 *   supports.
 *
 *   Returns <0 on error, and 0 on success
 **/
int nvm_erase_ppa(struct nvm_dev *dev, struct ppa_addr *ppas, int nr_ppas)
{
	struct nvm_rq rqd;
	int ret;

	if (!dev->ops->erase_block)
		return 0;

	memset(&rqd, 0, sizeof(struct nvm_rq));

	ret = nvm_set_rqd_ppalist(dev, &rqd, ppas, nr_ppas);
	if (ret)
		return ret;

	nvm_generic_to_addr_mode(dev, &rqd);

	ret = dev->ops->erase_block(dev, &rqd);

	nvm_free_rqd_ppalist(dev, &rqd);

	return ret;
}
EXPORT_SYMBOL(nvm_erase_ppa);

/**
 * nvm_end_io - Complete a nvm_rq request
 * @rqd:    The &struct nvm_rq in question
 * @error:  error code, 0 if successful
 *
 * Description:
 *   nvm_end_io() completes the nvm_rq structure by storing error in the nvm_rq
 *   structure, followed by a call to its end_io callback. nvm_rq->end_io must
 *   be set before call.
 */
void nvm_end_io(struct nvm_rq *rqd, int error)
{
	rqd->error = error;
	rqd->end_io(rqd);
}
EXPORT_SYMBOL(nvm_end_io);

static void nvm_end_io_sync(struct nvm_rq *rqd)
{
	struct completion *waiting = rqd->wait;

	rqd->wait = NULL;

	complete(waiting);
}

/**
 * nvm_submit_ppa - Submit a list of ppas to device synchronously.
 * @dev:     The &struct nvm_dev in question
 * @ppas:     List of PPAs
 * @nr_ppas: Number of PPAs in ppa list
 * @opcode:  Device opcode to be sent with the device
 * @flags:   Specific flags that is passed into the resulting nvm_rq structure
 * @buf:     Data buffer for the PPAs listed
 * @len:     Length of buffer
 *
 * Description:
 *   nvm_submit_ppa() takes a list of generic address ppas, together with a data
 *   buffer and opcode, which creates a nvm_rq data structure to be sent to the
 *   underlying device. The function will execute this command synchronously and
 *   return the error, if any.
 *
 *   Returns <0 on error, 0 on success
 **/
int nvm_submit_ppa(struct nvm_dev *dev, struct ppa_addr *ppas, int nr_ppas,
				int opcode, int flags, void *buf, int len)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	struct nvm_rq rqd;
	struct bio *bio;
	int ret;
	unsigned long hang_check;

	bio = bio_map_kern(dev->q, buf, len, GFP_KERNEL);
	if (IS_ERR_OR_NULL(bio))
		return -ENOMEM;

	memset(&rqd, 0, sizeof(struct nvm_rq));
	ret = nvm_set_rqd_ppalist(dev, &rqd, ppas, nr_ppas);
	if (ret) {
		bio_put(bio);
		return ret;
	}

	rqd.opcode = opcode;
	rqd.bio = bio;
	rqd.wait = &wait;
	rqd.dev = dev;
	rqd.end_io = nvm_end_io_sync;
	rqd.flags = flags;
	nvm_generic_to_addr_mode(dev, &rqd);

	ret = dev->ops->submit_io(dev, &rqd);

	/* Prevent hang_check timer from firing at us during very long I/O */
	hang_check = sysctl_hung_task_timeout_secs;
	if (hang_check)
		while (!wait_for_completion_io_timeout(&wait, hang_check * (HZ/2)));
	else
		wait_for_completion_io(&wait);

	nvm_free_rqd_ppalist(dev, &rqd);

	return rqd.error;
}
EXPORT_SYMBOL(nvm_submit_ppa);

static int nvm_init_slc_tbl(struct nvm_dev *dev, struct nvm_id_group *grp)
{
	int i;

	dev->lps_per_blk = dev->pgs_per_blk;
	dev->lptbl = kcalloc(dev->lps_per_blk, sizeof(int), GFP_KERNEL);
	if (!dev->lptbl)
		return -ENOMEM;

	/* Just a linear array */
	for (i = 0; i < dev->lps_per_blk; i++)
		dev->lptbl[i] = i;

	return 0;
}

static int nvm_init_mlc_tbl(struct nvm_dev *dev, struct nvm_id_group *grp)
{
	int i, p;
	struct nvm_id_lp_mlc *mlc = &grp->lptbl.mlc;

	if (!mlc->num_pairs)
		return 0;

	dev->lps_per_blk = mlc->num_pairs;
	dev->lptbl = kcalloc(dev->lps_per_blk, sizeof(int), GFP_KERNEL);
	if (!dev->lptbl)
		return -ENOMEM;

	/* The lower page table encoding consists of a list of bytes, where each
	 * has a lower and an upper half. The first half byte maintains the
	 * increment value and every value after is an offset added to the
	 * previous incrementation value */
	dev->lptbl[0] = mlc->pairs[0] & 0xF;
	for (i = 1; i < dev->lps_per_blk; i++) {
		p = mlc->pairs[i >> 1];
		if (i & 0x1) /* upper */
			dev->lptbl[i] = dev->lptbl[i - 1] + ((p & 0xF0) >> 4);
		else /* lower */
			dev->lptbl[i] = dev->lptbl[i - 1] + (p & 0xF);
	}

	return 0;
}

static int nvm_core_init(struct nvm_dev *dev)
{
	struct nvm_id *id = &dev->identity;
	struct nvm_id_group *grp = &id->groups[0];

	/* device values */
	dev->nr_chnls = grp->num_ch;
	dev->luns_per_chnl = grp->num_lun;
	dev->pgs_per_blk = grp->num_pg;
	dev->blks_per_lun = grp->num_blk;
	dev->nr_planes = grp->num_pln;
	dev->sec_size = grp->csecs;
	dev->oob_size = grp->sos;
	dev->sec_per_pg = grp->fpg_sz / grp->csecs;
	dev->mccap = grp->mccap;
	memcpy(&dev->ppaf, &id->ppaf, sizeof(struct nvm_addr_format));

	dev->plane_mode = NVM_PLANE_SINGLE;
	dev->max_rq_size = dev->ops->max_phys_sect * dev->sec_size;

	if (grp->mtype != 0) {
		pr_err("nvm: memory type not supported\n");
		return -EINVAL;
	}

	switch (grp->fmtype) {
	case NVM_ID_FMTYPE_SLC:
		if (nvm_init_slc_tbl(dev, grp))
			return -ENOMEM;
		break;
	case NVM_ID_FMTYPE_MLC:
		if (nvm_init_mlc_tbl(dev, grp))
			return -ENOMEM;
		break;
	default:
		pr_err("nvm: flash type not supported\n");
		return -EINVAL;
	}

	if (!dev->lps_per_blk)
		pr_info("nvm: lower page programming table missing\n");

	if (grp->mpos & 0x020202)
		dev->plane_mode = NVM_PLANE_DOUBLE;
	if (grp->mpos & 0x040404)
		dev->plane_mode = NVM_PLANE_QUAD;

	/* calculated values */
	dev->sec_per_pl = dev->sec_per_pg * dev->nr_planes;
	dev->sec_per_blk = dev->sec_per_pl * dev->pgs_per_blk;
	dev->sec_per_lun = dev->sec_per_blk * dev->blks_per_lun;
	dev->nr_luns = dev->luns_per_chnl * dev->nr_chnls;

	dev->total_blocks = dev->nr_planes *
				dev->blks_per_lun *
				dev->luns_per_chnl *
				dev->nr_chnls;
	dev->total_pages = dev->total_blocks * dev->pgs_per_blk;
	INIT_LIST_HEAD(&dev->online_targets);
	mutex_init(&dev->mlock);

	return 0;
}

static void nvm_free(struct nvm_dev *dev)
{
	if (!dev)
		return;

	if (dev->mt)
		dev->mt->unregister_mgr(dev);

	kfree(dev->lptbl);
}

static int nvm_init(struct nvm_dev *dev)
{
	int ret = -EINVAL;

	if (!dev->q || !dev->ops)
		return ret;

	if (dev->ops->identity(dev, &dev->identity)) {
		pr_err("nvm: device could not be identified\n");
		goto err;
	}

	pr_debug("nvm: ver:%x nvm_vendor:%x groups:%u\n",
			dev->identity.ver_id, dev->identity.vmnt,
							dev->identity.cgrps);

	if (dev->identity.ver_id != 1) {
		pr_err("nvm: device not supported by kernel.");
		goto err;
	}

	if (dev->identity.cgrps != 1) {
		pr_err("nvm: only one group configuration supported.");
		goto err;
	}

	ret = nvm_core_init(dev);
	if (ret) {
		pr_err("nvm: could not initialize core structures.\n");
		goto err;
	}

	pr_info("nvm: registered %s [%u/%u/%u/%u/%u/%u]\n",
			dev->name, dev->sec_per_pg, dev->nr_planes,
			dev->pgs_per_blk, dev->blks_per_lun, dev->nr_luns,
			dev->nr_chnls);
	return 0;
err:
	pr_err("nvm: failed to initialize nvm\n");
	return ret;
}

static void nvm_exit(struct nvm_dev *dev)
{
	if (dev->ppalist_pool)
		dev->ops->destroy_dma_pool(dev->ppalist_pool);
	nvm_free(dev);

	pr_info("nvm: successfully unloaded\n");
}

/**
 * nvm_register - Register a device with the LightNVM subsystem
 * @q:         The &struct request_queue of the device
 * @disk_name: The string name of the device
 * @ops:       The callbacks used by the LightNVM core to interact with the
 *             device.
 *
 * Description:
 *   nvm_register() registers a device with the LightNVM subsystem. It validates
 *   nvm_dev_ops and instantiates the appropriate media manager. If a device
 *   have previously been initialized, it will furthermore instantiate the
 *   associated media manager.
 *
 *   Returns <0 on error, 0 on success
 **/
int nvm_register(struct request_queue *q, char *disk_name,
							struct nvm_dev_ops *ops)
{
	struct nvm_dev *dev;
	int ret;

	if (!ops->identity)
		return -EINVAL;

	dev = kzalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->q = q;
	dev->ops = ops;
	strncpy(dev->name, disk_name, DISK_NAME_LEN);

	ret = nvm_init(dev);
	if (ret)
		goto err_init;

	if (dev->ops->max_phys_sect > 256) {
		pr_info("nvm: max sectors supported is 256.\n");
		ret = -EINVAL;
		goto err_init;
	}

	if (dev->ops->max_phys_sect > 1) {
		dev->ppalist_pool = dev->ops->create_dma_pool(dev, "ppalist");
		if (!dev->ppalist_pool) {
			pr_err("nvm: could not create ppa pool\n");
			ret = -ENOMEM;
			goto err_init;
		}
	}

	ret = nvm_get_sysblock(dev, &dev->sb);
	if (!ret)
		pr_err("nvm: device not initialized.\n");
	else if (ret < 0)
		pr_err("nvm: err (%d) on device initialization\n", ret);

	/* register device with a supported media manager */
	down_write(&nvm_lock);
	if (ret > 0)
		dev->mt = nvm_init_mgr(dev);
	list_add(&dev->devices, &nvm_devices);
	up_write(&nvm_lock);

	return 0;
err_init:
	kfree(dev);
	return ret;
}
EXPORT_SYMBOL(nvm_register);

/**
 * nvm_unregister - Unregister a device from the LightNVM subsystem
 * @disk_name:    Device name used for registering the device
 *
 * Description:
 *   nvm_unregister() removes a previously registered device from the LightNVM
 *   subsystem. If found, it will also call ->exit on the associated media
 *   manager to perform shutdown of its instantiated structures.
 **/
void nvm_unregister(char *disk_name)
{
	struct nvm_dev *dev;

	down_write(&nvm_lock);
	dev = nvm_find_nvm_dev(disk_name);
	if (!dev) {
		pr_err("nvm: could not find device %s to unregister\n",
								disk_name);
		up_write(&nvm_lock);
		return;
	}

	list_del(&dev->devices);
	up_write(&nvm_lock);

	nvm_exit(dev);
	kfree(dev);
}
EXPORT_SYMBOL(nvm_unregister);

static const struct block_device_operations nvm_fops = {
	.owner		= THIS_MODULE,
};

static int nvm_create_target(struct nvm_dev *dev,
						struct nvm_ioctl_create *create)
{
	struct nvm_ioctl_create_simple *s = &create->conf.s;
	struct request_queue *tqueue;
	struct gendisk *tdisk;
	struct nvm_tgt_type *tt;
	struct nvm_target *t;
	void *targetdata;

	if (!dev->mt) {
		pr_info("nvm: device has no media manager registered.\n");
		return -ENODEV;
	}

	down_write(&nvm_lock);
	tt = nvm_find_target_type(create->tgttype);
	if (!tt) {
		pr_err("nvm: target type %s not found\n", create->tgttype);
		up_write(&nvm_lock);
		return -EINVAL;
	}

	list_for_each_entry(t, &dev->online_targets, list) {
		if (!strcmp(create->tgtname, t->disk->disk_name)) {
			pr_err("nvm: target name already exists.\n");
			up_write(&nvm_lock);
			return -EINVAL;
		}
	}
	up_write(&nvm_lock);

	t = kmalloc(sizeof(struct nvm_target), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	tqueue = blk_alloc_queue_node(GFP_KERNEL, dev->q->node);
	if (!tqueue)
		goto err_t;
	blk_queue_make_request(tqueue, tt->make_rq);

	tdisk = alloc_disk(0);
	if (!tdisk)
		goto err_queue;

	sprintf(tdisk->disk_name, "%s", create->tgtname);
	tdisk->flags = GENHD_FL_EXT_DEVT;
	tdisk->major = 0;
	tdisk->first_minor = 0;
	tdisk->fops = &nvm_fops;
	tdisk->queue = tqueue;

	targetdata = tt->init(dev, tdisk, s->lun_begin, s->lun_end);
	if (IS_ERR(targetdata))
		goto err_init;

	tdisk->private_data = targetdata;
	tqueue->queuedata = targetdata;

	blk_queue_max_hw_sectors(tqueue, 8 * dev->ops->max_phys_sect);

	set_capacity(tdisk, tt->capacity(targetdata));
	add_disk(tdisk);

	t->type = tt;
	t->disk = tdisk;

	down_write(&nvm_lock);
	list_add_tail(&t->list, &dev->online_targets);
	up_write(&nvm_lock);

	return 0;
err_init:
	put_disk(tdisk);
err_queue:
	blk_cleanup_queue(tqueue);
err_t:
	kfree(t);
	return -ENOMEM;
}

static void nvm_remove_target(struct nvm_target *t)
{
	struct nvm_tgt_type *tt = t->type;
	struct gendisk *tdisk = t->disk;
	struct request_queue *q = tdisk->queue;

	lockdep_assert_held(&nvm_lock);

	del_gendisk(tdisk);
	blk_cleanup_queue(q);

	if (tt->exit)
		tt->exit(tdisk->private_data);

	put_disk(tdisk);

	list_del(&t->list);
	kfree(t);
}

static int __nvm_configure_create(struct nvm_ioctl_create *create)
{
	struct nvm_dev *dev;
	struct nvm_ioctl_create_simple *s;

	down_write(&nvm_lock);
	dev = nvm_find_nvm_dev(create->dev);
	up_write(&nvm_lock);
	if (!dev) {
		pr_err("nvm: device not found\n");
		return -EINVAL;
	}

	if (create->conf.type != NVM_CONFIG_TYPE_SIMPLE) {
		pr_err("nvm: config type not valid\n");
		return -EINVAL;
	}
	s = &create->conf.s;

	if (s->lun_begin > s->lun_end || s->lun_end > dev->nr_luns) {
		pr_err("nvm: lun out of bound (%u:%u > %u)\n",
			s->lun_begin, s->lun_end, dev->nr_luns);
		return -EINVAL;
	}

	return nvm_create_target(dev, create);
}

static int __nvm_configure_remove(struct nvm_ioctl_remove *remove)
{
	struct nvm_target *t = NULL;
	struct nvm_dev *dev;
	int ret = -1;

	down_write(&nvm_lock);
	list_for_each_entry(dev, &nvm_devices, devices)
		list_for_each_entry(t, &dev->online_targets, list) {
			if (!strcmp(remove->tgtname, t->disk->disk_name)) {
				nvm_remove_target(t);
				ret = 0;
				break;
			}
		}
	up_write(&nvm_lock);

	if (ret) {
		pr_err("nvm: target \"%s\" doesn't exist.\n", remove->tgtname);
		return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_NVM_DEBUG
static int nvm_configure_show(const char *val)
{
	struct nvm_dev *dev;
	char opcode, devname[DISK_NAME_LEN];
	int ret;

	ret = sscanf(val, "%c %32s", &opcode, devname);
	if (ret != 2) {
		pr_err("nvm: invalid command. Use \"opcode devicename\".\n");
		return -EINVAL;
	}

	down_write(&nvm_lock);
	dev = nvm_find_nvm_dev(devname);
	up_write(&nvm_lock);
	if (!dev) {
		pr_err("nvm: device not found\n");
		return -EINVAL;
	}

	if (!dev->mt)
		return 0;

	dev->mt->lun_info_print(dev);

	return 0;
}

static int nvm_configure_remove(const char *val)
{
	struct nvm_ioctl_remove remove;
	char opcode;
	int ret;

	ret = sscanf(val, "%c %256s", &opcode, remove.tgtname);
	if (ret != 2) {
		pr_err("nvm: invalid command. Use \"d targetname\".\n");
		return -EINVAL;
	}

	remove.flags = 0;

	return __nvm_configure_remove(&remove);
}

static int nvm_configure_create(const char *val)
{
	struct nvm_ioctl_create create;
	char opcode;
	int lun_begin, lun_end, ret;

	ret = sscanf(val, "%c %256s %256s %48s %u:%u", &opcode, create.dev,
						create.tgtname, create.tgttype,
						&lun_begin, &lun_end);
	if (ret != 6) {
		pr_err("nvm: invalid command. Use \"opcode device name tgttype lun_begin:lun_end\".\n");
		return -EINVAL;
	}

	create.flags = 0;
	create.conf.type = NVM_CONFIG_TYPE_SIMPLE;
	create.conf.s.lun_begin = lun_begin;
	create.conf.s.lun_end = lun_end;

	return __nvm_configure_create(&create);
}


/* Exposes administrative interface through /sys/module/lnvm/configure_by_str */
static int nvm_configure_by_str_event(const char *val,
					const struct kernel_param *kp)
{
	char opcode;
	int ret;

	ret = sscanf(val, "%c", &opcode);
	if (ret != 1) {
		pr_err("nvm: string must have the format of \"cmd ...\"\n");
		return -EINVAL;
	}

	switch (opcode) {
	case 'a':
		return nvm_configure_create(val);
	case 'd':
		return nvm_configure_remove(val);
	case 's':
		return nvm_configure_show(val);
	default:
		pr_err("nvm: invalid command\n");
		return -EINVAL;
	}

	return 0;
}

static int nvm_configure_get(char *buf, const struct kernel_param *kp)
{
	int sz = 0;
	char *buf_start = buf;
	struct nvm_dev *dev;

	buf += sprintf(buf, "available devices:\n");
	down_write(&nvm_lock);
	list_for_each_entry(dev, &nvm_devices, devices) {
		if (sz > 4095 - DISK_NAME_LEN)
			break;
		buf += sprintf(buf, " %32s\n", dev->name);
	}
	up_write(&nvm_lock);

	return buf - buf_start - 1;
}

static const struct kernel_param_ops nvm_configure_by_str_event_param_ops = {
	.set	= nvm_configure_by_str_event,
	.get	= nvm_configure_get,
};

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX	"lnvm."

module_param_cb(configure_debug, &nvm_configure_by_str_event_param_ops, NULL,
									0644);

#endif /* CONFIG_NVM_DEBUG */

static long nvm_ioctl_info(struct file *file, void __user *arg)
{
	struct nvm_ioctl_info *info;
	struct nvm_tgt_type *tt;
	int tgt_iter = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	info = memdup_user(arg, sizeof(struct nvm_ioctl_info));
	if (IS_ERR(info))
		return -EFAULT;

	info->version[0] = NVM_VERSION_MAJOR;
	info->version[1] = NVM_VERSION_MINOR;
	info->version[2] = NVM_VERSION_PATCH;

	down_write(&nvm_lock);
	list_for_each_entry(tt, &nvm_targets, list) {
		struct nvm_ioctl_info_tgt *tgt = &info->tgts[tgt_iter];

		tgt->version[0] = tt->version[0];
		tgt->version[1] = tt->version[1];
		tgt->version[2] = tt->version[2];
		strncpy(tgt->tgtname, tt->name, NVM_TTYPE_NAME_MAX);

		tgt_iter++;
	}

	info->tgtsize = tgt_iter;
	up_write(&nvm_lock);

	if (copy_to_user(arg, info, sizeof(struct nvm_ioctl_info))) {
		kfree(info);
		return -EFAULT;
	}

	kfree(info);
	return 0;
}

static long nvm_ioctl_get_devices(struct file *file, void __user *arg)
{
	struct nvm_ioctl_get_devices *devices;
	struct nvm_dev *dev;
	int i = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	devices = kzalloc(sizeof(struct nvm_ioctl_get_devices), GFP_KERNEL);
	if (!devices)
		return -ENOMEM;

	down_write(&nvm_lock);
	list_for_each_entry(dev, &nvm_devices, devices) {
		struct nvm_ioctl_device_info *info = &devices->info[i];

		sprintf(info->devname, "%s", dev->name);
		if (dev->mt) {
			info->bmversion[0] = dev->mt->version[0];
			info->bmversion[1] = dev->mt->version[1];
			info->bmversion[2] = dev->mt->version[2];
			sprintf(info->bmname, "%s", dev->mt->name);
		} else {
			sprintf(info->bmname, "none");
		}

		i++;
		if (i > 31) {
			pr_err("nvm: max 31 devices can be reported.\n");
			break;
		}
	}
	up_write(&nvm_lock);

	devices->nr_devices = i;

	if (copy_to_user(arg, devices,
			 sizeof(struct nvm_ioctl_get_devices))) {
		kfree(devices);
		return -EFAULT;
	}

	kfree(devices);
	return 0;
}

static long nvm_ioctl_dev_create(struct file *file, void __user *arg)
{
	struct nvm_ioctl_create create;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&create, arg, sizeof(struct nvm_ioctl_create)))
		return -EFAULT;

	create.dev[DISK_NAME_LEN - 1] = '\0';
	create.tgttype[NVM_TTYPE_NAME_MAX - 1] = '\0';
	create.tgtname[DISK_NAME_LEN - 1] = '\0';

	if (create.flags != 0) {
		pr_err("nvm: no flags supported\n");
		return -EINVAL;
	}

	return __nvm_configure_create(&create);
}

static long nvm_ioctl_dev_remove(struct file *file, void __user *arg)
{
	struct nvm_ioctl_remove remove;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&remove, arg, sizeof(struct nvm_ioctl_remove)))
		return -EFAULT;

	remove.tgtname[DISK_NAME_LEN - 1] = '\0';

	if (remove.flags != 0) {
		pr_err("nvm: no flags supported\n");
		return -EINVAL;
	}

	return __nvm_configure_remove(&remove);
}

static void nvm_setup_nvm_sb_info(struct nvm_sb_info *info)
{
	info->seqnr = 1;
	info->erase_cnt = 0;
	info->version = 1;
}

static long __nvm_ioctl_dev_init(struct nvm_ioctl_dev_init *init)
{
	struct nvm_dev *dev;
	struct nvm_sb_info info;
	int ret;

	down_write(&nvm_lock);
	dev = nvm_find_nvm_dev(init->dev);
	up_write(&nvm_lock);
	if (!dev) {
		pr_err("nvm: device not found\n");
		return -EINVAL;
	}

	nvm_setup_nvm_sb_info(&info);

	strncpy(info.mmtype, init->mmtype, NVM_MMTYPE_LEN);
	info.fs_ppa.ppa = -1;

	ret = nvm_init_sysblock(dev, &info);
	if (ret)
		return ret;

	memcpy(&dev->sb, &info, sizeof(struct nvm_sb_info));

	down_write(&nvm_lock);
	dev->mt = nvm_init_mgr(dev);
	up_write(&nvm_lock);

	return 0;
}

static long nvm_ioctl_dev_init(struct file *file, void __user *arg)
{
	struct nvm_ioctl_dev_init init;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&init, arg, sizeof(struct nvm_ioctl_dev_init)))
		return -EFAULT;

	if (init.flags != 0) {
		pr_err("nvm: no flags supported\n");
		return -EINVAL;
	}

	init.dev[DISK_NAME_LEN - 1] = '\0';

	return __nvm_ioctl_dev_init(&init);
}

static long nvm_ioctl_dev_factory(struct file *file, void __user *arg)
{
	struct nvm_ioctl_dev_factory fact;
	struct nvm_dev *dev;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&fact, arg, sizeof(struct nvm_ioctl_dev_factory)))
		return -EFAULT;

	fact.dev[DISK_NAME_LEN - 1] = '\0';

	if (fact.flags & ~(NVM_FACTORY_NR_BITS - 1))
		return -EINVAL;

	down_write(&nvm_lock);
	dev = nvm_find_nvm_dev(fact.dev);
	up_write(&nvm_lock);
	if (!dev) {
		pr_err("nvm: device not found\n");
		return -EINVAL;
	}

	if (dev->mt) {
		dev->mt->unregister_mgr(dev);
		dev->mt = NULL;
	}

	return nvm_dev_factory(dev, fact.flags);
}

static long nvm_ctl_ioctl(struct file *file, uint cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case NVM_INFO:
		return nvm_ioctl_info(file, argp);
	case NVM_GET_DEVICES:
		return nvm_ioctl_get_devices(file, argp);
	case NVM_DEV_CREATE:
		return nvm_ioctl_dev_create(file, argp);
	case NVM_DEV_REMOVE:
		return nvm_ioctl_dev_remove(file, argp);
	case NVM_DEV_INIT:
		return nvm_ioctl_dev_init(file, argp);
	case NVM_DEV_FACTORY:
		return nvm_ioctl_dev_factory(file, argp);
	}
	return 0;
}

static const struct file_operations _ctl_fops = {
	.open = nonseekable_open,
	.unlocked_ioctl = nvm_ctl_ioctl,
	.owner = THIS_MODULE,
	.llseek  = noop_llseek,
};

static struct miscdevice _nvm_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "lightnvm",
	.nodename	= "lightnvm/control",
	.fops		= &_ctl_fops,
};

MODULE_ALIAS_MISCDEV(MISC_DYNAMIC_MINOR);

static int __init nvm_mod_init(void)
{
	int ret;

	ret = misc_register(&_nvm_misc);
	if (ret)
		pr_err("nvm: misc_register failed for control device");

	return ret;
}

static void __exit nvm_mod_exit(void)
{
	misc_deregister(&_nvm_misc);
}

MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1");
module_init(nvm_mod_init);
module_exit(nvm_mod_exit);
