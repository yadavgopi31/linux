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

static int dflash_setup_rq(struct dflash *dflash, struct bio *bio,
					struct nvm_rq *rqd, uint8_t npages)
{
	struct nvm_dev *dev = dflash->dev;
	struct ppa_addr ppa;
	sector_t laddr = dflash_get_laddr(bio);
	sector_t ltmp = laddr;
	struct dflash_lun *nlun;
	int i;

	nlun = &dflash->luns[laddr / dev->sec_per_lun];
	ppa.ppa = 0;
	ppa.g.lun = nlun->parent->lun_id;
	ppa.g.ch = nlun->parent->chnl_id;
	ppa.g.blk = (laddr / dev->sec_per_blk) % dev->blks_per_lun;
	ppa.g.sec = laddr % dev->sec_per_pg;
	ppa.g.pl = (laddr % dev->sec_per_pl) / dev->nr_planes;
	ppa.g.pg = (laddr % dev->sec_per_blk) / (dev->sec_per_pl);

	/* pr_info("device charac - sec_per_blk:%d,blks_per_lun:%d, " */
	/*	"sec_per_pl:%d, sec_per_pg:%d,nr_planes:%d\n", */
	/*	dev->sec_per_blk, dev->blks_per_lun, */
	/*	dev->sec_per_pl, dev->sec_per_pg, dev->nr_planes); */

	/* the first block of a lun is used internally. */
	/* also block the last block access on partition scans. */
	if (ppa.g.blk == 0 || (ppa.g.ch == 15 && ppa.g.blk == 1023))
		return NVM_IO_DONE;
	/* if (npages == 1) { */
	/* 	pr_info("addr: %llu[%u]: ch: %u sec: %u pl: %u lun: %u pg: %u blk: %u -> %llu 0x%x\n", */
	/* 			(unsigned long long) ltmp, npages, */
	/* 			ppa.g.ch,ppa.g.sec, */
	/* 			ppa.g.pl,ppa.g.lun, */
	/* 			ppa.g.pg,ppa.g.blk, */
	/* 			ppa.ppa,ppa.ppa); */
	/* } */

	if (npages > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(dflash->dev, GFP_KERNEL,
							&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("dflash: can not allocate ppa list\n");
			return NVM_IO_ERR;
		}

		for (i = 0; i < npages; i++) {
			BUG_ON(!(laddr + i >= 0 && laddr + i < dflash->nr_pages));
			rqd->ppa_list[i] = ppa;
			/* pr_info("addr: %llu[%u]: ch: %u sec: %u pl: %u lun: %u pg: %u blk: %u -> %llu 0x%x\n",
			 *		(unsigned long long) ltmp, npages,
			 *		ppa.g.ch,ppa.g.sec,
			 *		ppa.g.pl,ppa.g.lun,
			 *		ppa.g.pg,ppa.g.blk,
			 *		ppa.ppa,ppa.ppa);
			 */
			ltmp++;
			ppa.g.sec = ltmp % dev->sec_per_pg;
			ppa.g.pl = (ltmp % dev->sec_per_pl) / dev->nr_planes;
			ppa.g.pg = (ltmp % dev->sec_per_blk) / dev->sec_per_pl;
		}

		return NVM_IO_OK;
	}

	rqd->ppa_addr = ppa;

	return NVM_IO_OK;
}

static int dflash_submit_io(struct dflash *dflash, struct bio *bio,
							struct nvm_rq *rqd)
{
	int err;
	uint8_t npages = dflash_get_pages(bio);

	err = dflash_setup_rq(dflash, bio, rqd, npages);
	if (err)
		return err;

	bio_get(bio);
	rqd->bio = bio;
	rqd->ins = &dflash->instance;
	rqd->nr_ppas = npages;

	if (bio_data_dir(bio) == WRITE) {
		rqd->opcode = NVM_OP_PWRITE;
		rqd->flags |= NVM_IO_QUAD_ACCESS;
	} else {
		rqd->opcode = NVM_OP_PREAD;
		rqd->flags |= NVM_IO_SUSPEND;

		/* Expose flags to the application */
		if (npages == 2) {
			pr_info("DUAL!\n");
			rqd->flags |= NVM_IO_DUAL_ACCESS;
		} else if (npages > 2) {
			pr_info("QUAD\n");
			rqd->flags |= NVM_IO_QUAD_ACCESS;
		}
	}

	err = nvm_submit_io(dflash->dev, rqd);
	if (err) {
		pr_err("rrpc: IO submission failed: %d\n", err);
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

static blk_qc_t dflash_make_rq(struct request_queue *q, struct bio *bio)
{
	struct dflash *dflash;
	struct nvm_rq *rqd;

	if (bio->bi_rw & REQ_OP_DISCARD)
		return BLK_QC_T_NONE;

	dflash = q->queuedata;

	rqd = mempool_alloc(dflash->rq_pool, GFP_KERNEL);
	if (!rqd) {
		pr_err_ratelimited("dflash: not able to queue bio.");
		bio_io_error(bio);
		return BLK_QC_T_NONE;
	}
	memset(rqd, 0, sizeof(struct nvm_rq));

	switch (dflash_submit_io(dflash, bio, rqd)) {
	case NVM_IO_OK:
		return BLK_QC_T_NONE;
	case NVM_IO_DONE:
		bio_endio(bio);
		break;
	case NVM_IO_ERR:
		bio_io_error(bio);
		break;
	default:
		break;
	}

	mempool_free(rqd, dflash->rq_pool);
	return BLK_QC_T_NONE;
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
		pr_err("nvm: dflash: could not initialize luns\n");
		goto clean;
	}

	ret = dflash_core_init(dflash);
	if (ret) {
		pr_err("nvm: dflash: could not initialize core\n");
		goto clean;
	}

	tdisk->fops = &dflash_fops;
	tdisk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO|GENHD_FL_NO_PART_SCAN;

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	pr_info("nvm: dflash initialized dflash %lu luns, %lu blocks and %lu pages\n",
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

static int dflash_ioctl(struct block_device *bdev, fmode_t mode,
					unsigned int cmd, unsigned long arg)
{
	struct dflash *dflash = bdev->bd_disk->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case NVM_BLOCK_GET:
		return dflash_ioctl_get_block(dflash, argp);
	case NVM_BLOCK_PUT:
		return dflash_ioctl_put_block(dflash, argp);
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

static struct nvm_tgt_type tt_dflash = {
	.name		= "dflash",
	.version	= {0, 0, 1},

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
