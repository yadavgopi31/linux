/*
 * Copyright (C) 2015 CNEX Labs. All rights reserved.
 * Initial release:
 *	- Javier González <javier@cnexlabs.com>
 *	- Matias Bjorling <matias@cnexlabs.com>
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
 */

#include "dflash.h"

static struct kmem_cache *dflash_rq_cache;
static DECLARE_RWSEM(dflash_lock);
extern const struct block_device_operations dflash_fops;

static int dflash_setup_rq(struct dflash *dflash, struct nvm_rq *rqd,
						struct nvm_ioctl_io *io)
{
	struct nvm_dev *dev = dflash->dev;
	struct ppa_addr ppas[64];
	int i, nppas, ret = 0;

	nppas = io->nppas;

	if (nppas == 1) {
		struct ppa_addr ppa;
		ppa.ppa = io->ppas;
		rqd->ppa_addr = generic_to_dev_addr(dev, ppa);
		return 0;
	}

	rqd->ppa_list = nvm_dev_dma_alloc(dev, GFP_KERNEL,
							&rqd->dma_ppa_list);
	if (!rqd->ppa_list)
		return NVM_IO_ERR;

	if (copy_from_user(ppas, (void __user *)io->ppas, sizeof(u64) * io->nppas)) {
		ret = -EFAULT;
		goto out_free_ppa_list;
	}

	for (i = 0; i < nppas; i++) {
		rqd->ppa_list[i] = generic_to_dev_addr(dev, ppas[i]);
		pr_info("addr: %i ch: %u sec: %u pl: %u lun: %u pg: %u blk: %u -> dev 0x%llx\n",
				i,
				ppas[i].g.ch,ppas[i].g.sec,
				ppas[i].g.pl,ppas[i].g.lun,
				ppas[i].g.pg,ppas[i].g.blk,
				rqd->ppa_list[i].ppa);
	}

	return 0;
out_free_ppa_list:
	nvm_dev_dma_free(dev, rqd->ppa_list, rqd->dma_ppa_list);
	return ret;
}

static int dflash_submit_io(struct dflash *dflash, struct nvm_rq *rqd,
						struct nvm_ioctl_io *io)
{
	struct nvm_dev *dev = dflash->dev;
	int ret;

	ret = dflash_setup_rq(dflash, rqd, io);
	if (ret)
		return ret;

	rqd->ins = &dflash->instance;
	rqd->nr_ppas = io->nppas;
	rqd->flags |= io->flags;

	if (io->opcode & 1) {
		rqd->opcode = NVM_OP_PWRITE;
	} else {
		rqd->opcode = NVM_OP_PREAD;
		rqd->flags |= NVM_IO_SUSPEND;
	}

	io->result = dev->ops->submit_user_io(dflash->dev, rqd,
						(void *)io->addr, io->data_len);
	io->status = rqd->ppa_status;

	return 0;
}

static void dflash_end_io(struct nvm_rq *rqd)
{
	struct dflash *dflash = container_of(rqd->ins, struct dflash, instance);
	uint8_t npages = rqd->nr_ppas;

	bio_put(rqd->bio);

	if (npages > 1)
		nvm_dev_dma_free(dflash->dev, rqd->ppa_list, rqd->dma_ppa_list);

	mempool_free(rqd, dflash->rq_pool);
}

static sector_t dflash_capacity(void *private)
{
	struct dflash *dflash = private;

	return dflash->nr_pages * NR_PHY_IN_LOG;
}

static void dflash_core_free(struct dflash *dflash)
{
	mempool_destroy(dflash->rq_pool);
}

static void dflash_luns_free(struct dflash *dflash)
{
	kfree(dflash->luns);
}

static void dflash_free(struct dflash *dflash)
{
	if (dflash) {
		dflash_core_free(dflash);
		dflash_luns_free(dflash);
		kfree(dflash);
	}
}

static int dflash_luns_init(struct dflash *dflash, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = dflash->dev;
	struct nvm_lun *lun;
	struct nvm_block *block;

	struct dflash_lun *rlun;

	unsigned long j;
	unsigned long i;

	int ret = 0;

	dflash->luns = kcalloc(dflash->nr_luns, sizeof(struct dflash_lun),
								GFP_KERNEL);
	if (!dflash->luns)
		return -ENOMEM;

	dflash->nr_pages = dev->sec_per_lun * dflash->nr_luns;

	for (i = 0; i < dflash->nr_luns; ++i) {
		lun = dev->mt->get_lun(dev, lun_begin + i);

		rlun = &dflash->luns[i];

		rlun->dflash = dflash;
		rlun->parent = lun;
		rlun->nr_free_blocks = dev->blks_per_lun;

		/*
		 * FIXME: This allocation is a momentary fix until we fix the
		 *	  block id issue
		 */
		rlun->blocks = vzalloc(sizeof(struct nvm_block) *
							dev->blks_per_lun);
		if (!rlun->blocks) {
			ret = -ENOMEM;
			goto out;
		}

		for (j = 0; j < rlun->nr_free_blocks; ++j) {
			block = &rlun->blocks[j];

			/* FIXME
			 * spin_lock_init(&block->lock);
			 */
			INIT_LIST_HEAD(&block->list);

			/* FIXME
			 * bitmap_zero(block->invalid_pages, lun->pgs_per_blk);
			 * block->next_page = 0;
			 * block->nr_invalid_pages = 0;
			 * atomic_set(&block->data_cmnt_size, 0);
			 */
		}
	}

out:
	return ret;
}

static int dflash_core_init(struct dflash *dflash)
{
	down_write(&dflash_lock);
	dflash_rq_cache = kmem_cache_create("dflash_rq", sizeof(struct nvm_rq),
							0, 0, NULL);
	if (!dflash_rq_cache) {
		up_write(&dflash_lock);
		return -ENOMEM;
	}
	up_write(&dflash_lock);

	dflash->rq_pool = mempool_create_slab_pool(64, dflash_rq_cache);
	if (!dflash->rq_pool)
		return -ENOMEM;

	return 0;
}

static struct nvm_tgt_type tt_dflash;

static void *dflash_init(struct nvm_dev *dev, struct gendisk *tdisk,
						int lun_begin, int lun_end)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct dflash *dflash;
	int ret;

	dflash = kzalloc(sizeof(struct dflash), GFP_KERNEL);
	if (!dflash) {
		ret = -ENOMEM;
		goto err;
	}

	dflash->instance.tt = &tt_dflash;
	dflash->dev = dev;
	dflash->disk = tdisk;

	dflash->nr_luns = lun_end - lun_begin + 1;

	ret = dflash_luns_init(dflash, lun_begin, lun_end);
	if (ret) {
		pr_err("nvm-dflash: could not initialize luns\n");
		goto clean;
	}

	ret = dflash_core_init(dflash);
	if (ret) {
		pr_err("nvm-dflash: could not initialize core\n");
		goto clean;
	}

	tdisk->fops = &dflash_fops;
	tdisk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO|GENHD_FL_NO_PART_SCAN;

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	pr_info("nvm-dflash: initialized nr_luns(%lu), blocks(%lu), pages(%lu)\n",
		dflash->nr_luns,
		dflash->nr_luns * dev->blks_per_lun,
		dflash->nr_luns * dev->sec_per_lun);

	return dflash;
clean:
	dflash_free(dflash);
err:
	return ERR_PTR(ret);
}

static void dflash_exit(void *private)
{
	struct dflash *dflash = private;

	dflash_free(dflash);
}

/*
 * TODO: move .ioctl to .unlocked_ioctl and implement locking within the module
 */
static DEFINE_SPINLOCK(dev_list_lock);

static int dflash_ioctl_get_block(struct dflash *dflash, void __user *arg)
{
	struct nvm_ioctl_vblock vblock;
	struct dflash_lun *dflash_lun;
	struct nvm_dev *dev = dflash->dev;
	struct nvm_lun *lun;
	struct nvm_block *block;

	if (copy_from_user(&vblock, arg, sizeof(vblock)))
		return -EFAULT;

	if (!(vblock.flags & (NVM_PROV_SPEC_LUN | NVM_PROV_RAND_LUN)))
		return -EINVAL;

	if (vblock.flags & NVM_PROV_SPEC_LUN) {
		if (vblock.vlun_id >= dflash->nr_luns)
			return -EINVAL;
	} else {
		/* TODO: Implement function to choose lun */
		vblock.vlun_id = 0;
	}

	dflash_lun = &dflash->luns[vblock.vlun_id];
	lun = dflash_lun->parent;

	block = nvm_get_blk(dflash->dev, dflash_lun->parent, 0);
	if (!block)
		return -EFAULT;

	/* TODO: This should be moved to an internal function
	 *	 keep track of internal ids?
	 */
	dflash_lun->nr_free_blocks--;

	vblock.id = block->id;  /*	Blocks have a global id	*/
	vblock.bppa = dev->sec_per_blk * vblock.id;
	vblock.nppas = dev->pgs_per_blk * dev->sec_per_pg;

	nvm_erase_blk(dflash->dev, block);

	if (copy_to_user(arg, &vblock, sizeof(vblock)))
		return -EFAULT;

	return 0;
}

static int dflash_ioctl_put_block(struct dflash *dflash, void __user *arg)
{
	struct nvm_ioctl_vblock vblock;
	struct nvm_dev *dev = dflash->dev;
	struct dflash_lun *dflash_lun;
	struct nvm_block *block;
	struct nvm_lun *lun;

	if (copy_from_user(&vblock, arg, sizeof(vblock)))
		return -EFAULT;

	if (vblock.vlun_id >= dflash->nr_luns)
		return -EINVAL;

	dflash_lun = &dflash->luns[vblock.vlun_id];
	lun = dflash_lun->parent;
	if (vblock.id <= (lun->id * dev->blks_per_lun) ||
				vblock.id > ((lun->id + 1) * dev->blks_per_lun))
		return -EINVAL;

	block = &lun->blocks[vblock.id % dev->blks_per_lun];

	nvm_put_blk(dev, block);
	dflash_lun->nr_free_blocks++;

	return 0;
}

static int dflash_ioctl_user_io(struct dflash *df,
						struct nvm_ioctl_io __user *uio)
{
	struct nvm_ioctl_io io;
	struct nvm_rq *rqd;
	int ret;

	if (copy_from_user(&io, uio, sizeof(io)));
		return -EFAULT;

	rqd = mempool_alloc(df->rq_pool, GFP_KERNEL);
	if (!rqd)
		return -ENOMEM;
	memset(rqd, 0, sizeof(struct nvm_rq));

	ret = dflash_submit_io(df, rqd, &io);

	mempool_free(rqd, df->rq_pool);
	return ret;
}

static int dflash_ioctl(struct block_device *bdev, fmode_t mode,
					unsigned int cmd, unsigned long arg)
{
	struct dflash *dflash = bdev->bd_disk->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case NVM_PIO:
		return dflash_ioctl_user_io(dflash, (void __user *)argp);
	case NVM_BLOCK_GET:
		return dflash_ioctl_get_block(dflash, (void __user *)argp);
	case NVM_BLOCK_PUT:
		return dflash_ioctl_put_block(dflash, (void __user *)argp);
	default:
		return -ENOTTY;
	}
}

static int dflash_check_device(struct block_device *bdev)
{
	struct dflash *nb;
	int ret = 0;

	/* TODO: kref?*/
	spin_lock(&dev_list_lock);
	nb = bdev->bd_disk->private_data;
	if (!nb)
		ret = -ENXIO;
	spin_unlock(&dev_list_lock);

	return ret;
}

static int dflash_open(struct block_device *bdev, fmode_t mode)
{
	return dflash_check_device(bdev);
}

static void dflash_release(struct gendisk *disk, fmode_t mode)
{
}

const struct block_device_operations dflash_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= dflash_ioctl,
	.open		= dflash_open,
	.release	= dflash_release,
};
static blk_qc_t dflash_make_rq(struct request_queue *q, struct bio *bio)
{
	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static struct nvm_tgt_type tt_dflash = {
	.name		= "dflash",
	.version	= {0, 0, 1},

	/* TODO: make it a char dev instead */
	.make_rq	= dflash_make_rq,
	.capacity	= dflash_capacity,
	.end_io		= dflash_end_io,

	.init		= dflash_init,
	.exit		= dflash_exit,
};

static int __init dflash_module_init(void)
{
	return nvm_register_tgt_type(&tt_dflash);
}

static void dflash_module_exit(void)
{
	nvm_unregister_tgt_type(&tt_dflash);
}

module_init(dflash_module_init);
module_exit(dflash_module_exit);
MODULE_AUTHOR("Javier Gonzalez <javier@cnexlabs.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("liblightnvm support target");
