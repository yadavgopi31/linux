/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Matias Bjorling <m@bjorling.me>
 * Write buffering: Javier Gonzalez <jg@lightnvm.io>
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
 * Implementation of a physical block-device target for Open-channel SSDs.
 *
 * Derived from rrpc.c
 */

#include "pblk.h"
#include "pblk-recovery.h"

unsigned long pblk_r_rq_size, pblk_w_rq_size;
static struct kmem_cache *pblk_gcb_cache, *pblk_rec_cache, *pblk_r_rq_cache,
							*pblk_w_rq_cache;
static DECLARE_RWSEM(pblk_lock);
static int pblk_submit_io(struct pblk *pblk, struct bio *bio,
							unsigned long flags);
static void pblk_run_gc(struct pblk *pblk, struct pblk_block *rblk,
					void(*work)(struct work_struct *));

#define pblk_for_each_lun(pblk, rlun, i) \
		for ((i) = 0, rlun = &(pblk)->luns[0]; \
			(i) < (pblk)->nr_luns; (i)++, rlun = &(pblk)->luns[(i)])

/* The ppa in pblk_addr comes with an offset format, not a global format */
static void pblk_page_pad_invalidate(struct pblk *pblk, struct pblk_block *rblk,
							struct ppa_addr a)
{
	WARN_ON(test_and_set_bit(a.ppa, rblk->invalid_pages));
	rblk->nr_invalid_pages++;

	WARN_ON(test_and_set_bit(a.ppa, rblk->sync_bitmap));
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_gc(pblk, rblk, pblk_close_rblk_queue);
}

static void pblk_invalidate_range(struct pblk *pblk, sector_t slba,
							unsigned nr_secs)
{
	sector_t i;

	spin_lock(&pblk->trans_lock);
	for (i = slba; i < slba + nr_secs; i++) {
		struct pblk_addr *gp = &pblk->trans_map[i];

		pblk_page_invalidate(pblk, gp);
		ppa_set_empty(&gp->ppa);
		gp->rblk = NULL;
	}
	spin_unlock(&pblk->trans_lock);
}

static void pblk_discard(struct pblk *pblk, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t nr_secs = bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;

	pblk_invalidate_range(pblk, slba, nr_secs);
}

static inline u64 pblk_next_free_sec(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 free_sec;

	lockdep_assert_held(&rblk->lock);

	free_sec = find_first_zero_bit(rblk->pages, pblk->nr_blk_dsecs);
	WARN_ON(test_and_set_bit(free_sec, rblk->pages));

	return free_sec;
}

static inline u64 pblk_nr_free_secs(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 free_secs = pblk->nr_blk_dsecs;

	spin_lock(&rblk->lock);
	free_secs -= bitmap_weight(rblk->pages, pblk->nr_blk_dsecs);
	spin_unlock(&rblk->lock);

	return free_secs;
}

static void pblk_set_lun_cur(struct pblk_lun *rlun, struct pblk_block *rblk,
								int is_bb)
{
	struct pblk *pblk = rlun->pblk;
	struct nvm_lun *lun = rlun->parent;

	spin_lock(&lun->lock);
	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(pblk, rlun->cur) && !is_bb);
		spin_unlock(&rlun->cur->lock);
	}

	rlun->cur = rblk;
	spin_unlock(&lun->lock);
}

static void pblk_free_blk(struct pblk_block *rblk)
{
	if (rblk->pages) {
		kfree(rblk->pages);
		rblk->pages = NULL;
	}
	if (rblk->sync_bitmap) {
		kfree(rblk->sync_bitmap);
		rblk->sync_bitmap = NULL;
	}
	if (rblk->invalid_pages)
		kfree(rblk->invalid_pages);
	if (rblk->rlpg)
		kfree(rblk->rlpg);
}

static void pblk_free_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	unsigned int i;

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock);
		list_for_each_entry_safe(rblk, trblk, &rlun->prio_list, prio) {
			pblk_free_blk(rblk);
			list_del(&rblk->prio);
		}
		spin_unlock(&rlun->lock);
	}
}

static void __pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	nvm_put_blk(pblk->dev, rblk->parent);
	list_del(&rblk->list);
	pblk_free_blk(rblk);
}

static void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock_lists);
	__pblk_put_blk(pblk, rblk);
	spin_unlock(&rlun->lock_lists);
}

static void pblk_put_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		if (rlun->cur)
			pblk_put_blk(pblk, rlun->cur);
		if (rlun->gc_cur)
			pblk_put_blk(pblk, rlun->gc_cur);
	}
}

static struct pblk_block *pblk_get_blk(struct pblk *pblk, struct pblk_lun *rlun,
							unsigned long flags)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun = rlun->parent;
	struct nvm_block *blk;
	struct pblk_block *rblk;
	struct pblk_blk_rec_lpg *rlpg;
	unsigned long *sync_bitmap, *page_bitmap, *invalid_pages;
	int nr_entries = pblk->nr_blk_dsecs;
	unsigned int rlpg_len, req_len;

	sync_bitmap = kzalloc(BITS_TO_LONGS(nr_entries) *
					sizeof(unsigned long), GFP_KERNEL);
	if (!sync_bitmap) {
		pr_err("pblk: cannot allocate sync_bitmap for block\n");
		return NULL;
	}

	page_bitmap = kzalloc(BITS_TO_LONGS(nr_entries) *
					sizeof(unsigned long), GFP_KERNEL);
	if (!page_bitmap) {
		pr_err("pblk: cannot allocate page_bitmap for block\n");
		goto fail_alloc_page;
	}

	invalid_pages = kzalloc(BITS_TO_LONGS(nr_entries) *
					sizeof(unsigned long), GFP_KERNEL);
	if (!invalid_pages) {
		pr_err("pblk: cannot allocate invalid_pages for block\n");
		goto fail_alloc_invalid;
	}

	rlpg_len = sizeof(struct pblk_blk_rec_lpg) + (nr_entries * sizeof(u64));
	req_len = dev->sec_per_pl * dev->sec_size;
	rlpg = kzalloc(req_len, GFP_KERNEL);
	if (!rlpg) {
		pr_err("pblk: cannot allocate recovery ppa list\n");
		goto fail_alloc_rec;
	}
	rlpg->status = PBLK_BLK_ST_OPEN;
	rlpg->rlpg_len = rlpg_len;
	rlpg->req_len = req_len;
	rlpg->crc = 0;
	rlpg->nr_lbas = 0;
	rlpg->nr_padded = 0;

try:
	blk = nvm_get_blk(pblk->dev, lun, flags);
	if (!blk) {
		pr_err("pblk: cannot get new block from media manager\n");
		spin_unlock(&lun->lock);
		goto fail_get_blk;
	}

	rblk = pblk_get_rblk(rlun, blk->id);

	blk->priv = rblk;
	rblk->pages = page_bitmap;
	rblk->sync_bitmap = sync_bitmap;
	rblk->invalid_pages = invalid_pages;
	rblk->nr_invalid_pages = 0;
	rblk->rlpg = rlpg;

	spin_lock(&rlun->lock_lists);
	list_add_tail(&rblk->list, &rlun->open_list);
	spin_unlock(&rlun->lock_lists);

	if (nvm_erase_blk(dev, rblk->parent)) {
		struct ppa_addr ppa;

		pr_err("pblk: error while erasing block:%lu. Retry\n",
							rblk->parent->id);

		/* Mark block as bad and return it to media manager */
		ppa = pblk_ppa_to_gaddr(dev, block_to_addr(pblk, rblk));
		nvm_mark_blk(dev, ppa, NVM_BLK_ST_BAD);
		pblk_put_blk(pblk, rblk);

		goto try;
	}

	return rblk;

fail_get_blk:
	kfree(rlpg);
fail_alloc_rec:
	kfree(invalid_pages);
fail_alloc_invalid:
	kfree(page_bitmap);
fail_alloc_page:
	kfree(sync_bitmap);
	return NULL;
}

static inline void pblk_disable_lun(struct pblk_lun *rlun, struct nvm_lun *lun)
{
	spin_lock(&lun->lock);
	rlun->cur = NULL;
	spin_unlock(&lun->lock);
}

static int pblk_replace_blk(struct pblk *pblk, struct pblk_block *rblk,
					struct pblk_lun *rlun, int is_bb)
{
	struct nvm_lun *lun = rlun->parent;
	int ret = 0;

	pblk_disable_lun(rlun, lun);

	rblk = pblk_get_blk(pblk, rlun, 0);
	if (!rblk) {
		pr_err("pblk: cannot allocate new block\n");
		ret = -ENOSPC;
		goto out;
	}
	pblk_set_lun_cur(rlun, rblk, is_bb);

out:
	return ret;
}

/* static void pblk_lun_prov(struct work_struct *work) */
/* { */
	/* struct pblk_lun *rlun = container_of(work, struct pblk_lun, ws_prov); */
	/* struct pblk *pblk = rlun->pblk; */
	/* struct pblk_block *rblk; */
/*  */
	/* pblk_replace_blk(pblk, rblk, rlun, 1); */
/* } */

static struct pblk_lun *get_next_lun(struct pblk *pblk)
{
	int next = atomic_inc_return(&pblk->next_lun);

	return &pblk->luns[next % pblk->nr_luns];
}

static void pblk_gc_kick(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	unsigned int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		queue_work(pblk->krqd_wq, &rlun->ws_gc);
	}
}

static void pblk_write_kick(struct pblk *pblk)
{
	queue_work(pblk->kw_wq, &pblk->ws_writer);
}

static void pblk_run_gc(struct pblk *pblk, struct pblk_block *rblk,
					void(*work)(struct work_struct *))
{
	struct pblk_block_gc *gcb;

	gcb = mempool_alloc(pblk->gcb_pool, GFP_ATOMIC);
	if (!gcb) {
		pr_err("pblk: unable to queue block for gc.");
		return;
	}

	gcb->pblk = pblk;
	gcb->rblk = rblk;

	INIT_WORK(&gcb->ws_gc, work);
	queue_work(pblk->kgc_wq, &gcb->ws_gc);
}

/* TODO: Need to implement the different strategies */
int pblk_calc_secs_to_sync(struct pblk *pblk, unsigned long secs_avail,
				  unsigned long secs_to_flush)
{
	int max = pblk->max_write_pgs;
	int min = pblk->min_write_pgs;
	int sync = NVM_SYNC_HARD; /* TODO: Move to sysfs and put it in pblk */
	int secs_to_sync = 0;

	switch (sync) {
	case NVM_SYNC_SOFT:
		if (secs_avail >= max)
			secs_to_sync = max;
		break;
	case NVM_SYNC_HARD:
	case NVM_SYNC_OPORT:
		if ((secs_avail >= max) || (secs_to_flush >= max)) {
			secs_to_sync = max;
		} else if (secs_avail >= min) {
			if (secs_to_flush) {
				secs_to_sync = min * (secs_to_flush / min);
				while (1) {
					int inc = secs_to_sync + min;
					if (inc <= secs_avail && inc <= max)
						secs_to_sync += min;
					else
						break;
				}
			} else
				secs_to_sync = min * (secs_avail / min);
		} else {
			if (secs_to_flush && sync != NVM_SYNC_OPORT)
				secs_to_sync = min;
		}
	}

	BUG_ON(!secs_to_sync && secs_to_flush);

	return secs_to_sync;
}

static void pblk_gc_queue(struct work_struct *work)
{
	struct pblk_block_gc *gcb = container_of(work, struct pblk_block_gc,
									ws_gc);
	struct pblk *pblk = gcb->pblk;
	struct pblk_block *rblk = gcb->rblk;
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock_lists);
	list_move_tail(&rblk->list, &rlun->closed_list);
	spin_unlock(&rlun->lock_lists);

	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

	mempool_free(gcb, pblk->gcb_pool);
	pr_debug("nvm: block '%lu' is full, allow GC (sched)\n",
							rblk->parent->id);
}

/*
 * timed GC every interval.
 */
static void pblk_gc_timer(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	pblk_gc_kick(pblk);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(10));
}

void pblk_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	if (bio->bi_error)
		pr_err("pblk: sync request failed (%u).\n", bio->bi_error);

	complete(waiting);
}

static void pblk_end_close_blk_bio(struct pblk *pblk, struct nvm_rq *rqd,
				   int run_gc)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_close_ctx *c_ctx = ctx->c_ctx;

	if (run_gc)
		pblk_run_gc(pblk, c_ctx->rblk, pblk_gc_queue);

	nvm_free_rqd_ppalist(dev, rqd);
	bio_put(rqd->bio);
	kfree(rqd);
}

static void pblk_block_gc(struct work_struct *work)
{
	struct pblk_block_gc *gcb = container_of(work, struct pblk_block_gc,
									ws_gc);
	struct pblk *pblk = gcb->pblk;
	struct pblk_block *rblk = gcb->rblk;
	struct pblk_lun *rlun = rblk->rlun;
	/* struct nvm_dev *dev = pblk->dev; */

	// XXX: Prevent GC from running for now
	return;

	mempool_free(gcb, pblk->gcb_pool);
	pr_debug("pblk: block '%lu' being reclaimed\n", rblk->parent->id);

	/* if (pblk_move_valid_pages(pblk, rblk)) */
		/* goto put_back; */

	/* if (nvm_erase_blk(dev, rblk->parent)) */
		/* goto put_back; */

	/* pblk_put_blk(pblk, rblk); */
	return;

/* put_back: */
	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list
 */
static struct pblk_block *rblock_max_invalid(struct pblk_block *ra,
							struct pblk_block *rb)
{
	if (ra->nr_invalid_pages == rb->nr_invalid_pages)
		return ra;

	return (ra->nr_invalid_pages < rb->nr_invalid_pages) ? rb : ra;
}

/* linearly find the block with highest number of invalid pages
 * requires lun->lock
 */
static struct pblk_block *block_prio_find_max(struct pblk_lun *rlun)
{
	struct list_head *prio_list = &rlun->prio_list;
	struct pblk_block *rblk, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct pblk_block, prio);
	list_for_each_entry(rblk, prio_list, prio)
		max = rblock_max_invalid(max, rblk);

	return max;
}

static void pblk_lun_gc(struct work_struct *work)
{
	struct pblk_lun *rlun = container_of(work, struct pblk_lun, ws_gc);
	struct pblk *pblk = rlun->pblk;
	struct nvm_lun *lun = rlun->parent;
	struct pblk_block_gc *gcb;
	unsigned int nr_blocks_need;

	/* JAVIER: TO GO when enabling GC */
	return;

	nr_blocks_need = pblk->nr_luns *
				(pblk->dev->blks_per_lun / GC_LIMIT_INVERSE);

	if (nr_blocks_need < pblk->nr_luns)
		nr_blocks_need = pblk->nr_luns;

	spin_lock(&rlun->lock);
	while (nr_blocks_need > lun->nr_free_blocks &&
					!list_empty(&rlun->prio_list)) {
		struct pblk_block *rblk = block_prio_find_max(rlun);
		struct nvm_block *block = rblk->parent;

		if (!rblk->nr_invalid_pages)
			break;

		gcb = mempool_alloc(pblk->gcb_pool, GFP_ATOMIC);
		if (!gcb)
			break;

		list_del_init(&rblk->prio);

		BUG_ON(!block_is_full(pblk, rblk));

		/* We can free page bitmap at this point */
		kfree(rblk->pages);

		pr_debug("pblk: selected block '%lu' for GC\n", block->id);

		gcb->pblk = pblk;
		gcb->rblk = rblk;

		INIT_WORK(&gcb->ws_gc, pblk_block_gc);
		queue_work(pblk->kgc_wq, &gcb->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&rlun->lock);

	/* TODO: Hint that request queue can be started again */
}

static const struct block_device_operations pblk_fops = {
	.owner		= THIS_MODULE,
};

static struct pblk_lun *pblk_get_lun_rr(struct pblk *pblk, int is_gc)
{
	unsigned int i;
	struct pblk_lun *rlun, *max_free;

	if (!is_gc)
		return get_next_lun(pblk);

	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns.
	 */
	max_free = &pblk->luns[0];
	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate.
	 */
	pblk_for_each_lun(pblk, rlun, i) {
		if (rlun->parent->nr_free_blocks >
					max_free->parent->nr_free_blocks)
			max_free = rlun;
	}

	return max_free;
}

static u64 pblk_alloc_addr(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 addr = ADDR_EMPTY;

	lockdep_assert_held(&rblk->lock);

	if (block_is_full(pblk, rblk))
		goto out;

	addr = pblk_next_free_sec(pblk, rblk);

out:
	return addr;
}

#ifdef CONFIG_NVM_DEBUG
static inline u64 pblk_current_pg(struct pblk *pblk, struct pblk_block *rblk)
{
	int next_free_page;

	spin_lock(&rblk->lock);
	next_free_page = find_first_zero_bit(rblk->pages, pblk->nr_blk_dsecs);
	spin_unlock(&rblk->lock);

	return next_free_page;
}
#endif

static int pblk_map_page(struct pblk *pblk, struct pblk_block *rblk,
				unsigned int sentry, struct ppa_addr *ppa_list,
				struct pblk_sec_meta *meta_list,
				unsigned int nr_secs, unsigned int valid_secs)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_blk_rec_lpg *rlpg = rblk->rlpg;
	struct pblk_w_ctx *w_ctx;
	u64 *lba_list;
	u64 paddr;
	int i;

	lba_list = pblk_rlpg_to_llba(rlpg);

	spin_lock(&rblk->lock);
	for (i = 0; i < nr_secs; i++) {
		paddr = pblk_alloc_addr(pblk, rblk);
		if (paddr == ADDR_EMPTY) {
			/* We should always have available sectors for a full
			 * page write at this point. We get a new block for this
			 * LUN when the current block is full.
			 */
			pr_err("pblk: corrupted l2p mapping, blk:%lu\n",
					rblk->parent->id);
			return -EINVAL;
		}

		/* TODO: Implement GC path with emergency blocks */

		/* ppa to be sent to the device */
		ppa_list[i] =
			pblk_ppa_to_gaddr(dev, global_addr(pblk, rblk, paddr));

		/* write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and only one of the writer threads have access to each
		 * specific entry at a time. Thus, it is safe to modify the
		 * context for the entry we are setting up for submission
		 * without taking any lock and/or memory barrier.
		 */
		if (i < valid_secs) {
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->ppa.ppa = addr_to_ppa(paddr);
			w_ctx->ppa.rblk = rblk;
			meta_list[i].lba = w_ctx->lba;
			lba_list[paddr] = w_ctx->lba;
			rlpg->nr_lbas++;
		} else {
			meta_list[i].lba = ADDR_EMPTY;
			lba_list[paddr] = ADDR_EMPTY;
			/* invalidate padded ppas immediately */
			pblk_page_pad_invalidate(pblk, rblk,
							addr_to_ppa(paddr));
			rlpg->nr_padded++;
		}
	}
	spin_unlock(&rblk->lock);

	return 0;
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk. Mapping occurs at a page granurality, i.e., if a
 * page is 4 sectors, then each map entails 4 lba-ppa mappings - @nr_secs is the
 * number of sectors in the page, taking number of planes also into
 * consideration
 *
 * TODO: We are missing GC path
 * TODO: Add support for MLC and TLC padding. For now only supporting SLC
 */
static int pblk_map_rr_page(struct pblk *pblk, unsigned int sentry,
				struct ppa_addr *ppa_list,
				struct pblk_sec_meta *meta_list,
				unsigned int nr_secs, unsigned int valid_secs)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	struct nvm_lun *lun;
	int is_gc = 0; //TODO: Fix for now
	int ret = 0;

	rlun = pblk_get_lun_rr(pblk, is_gc);
	lun = rlun->parent;

try:
	/* TODO: This should follow a richer heuristic */
	if (lun->nr_free_blocks < pblk->nr_luns * 4) {
		//XXX: Other?
		printk(KERN_CRIT "NOT SPACE ON LUN\n");
		ret = -ENOSPC;
		goto out;
	}

	spin_lock(&rlun->lock);
	rblk = rlun->cur;

	/* In the case of a grown bad block, the assigned LUN might be
	 * recovering, i.e., retiring the bad block and setting a new one. Skip
	 * this block in this unusual case.
	 */
	if (!rblk) {
		spin_unlock(&rlun->lock);
		goto try;
	}

	/* Account for grown bad blocks */
	if (unlikely(block_is_bad(rblk))) {
		pblk_disable_lun(rlun, lun);
		spin_unlock(&rlun->lock);

		ret = pblk_replace_blk(pblk, rblk, rlun, 1);
		if (ret)
			goto out;

		goto try;
	}

	ret = pblk_map_page(pblk, rblk, sentry, ppa_list, meta_list,
							nr_secs, valid_secs);
	if (ret) {
		/* If mapping failed, there is not need to keep the reference.
		 * Otherwise, maintain it to ensure that rblk is not freed
		 * before completion (i.e., keep the reference).
		 */
		spin_unlock(&rlun->lock);
		ret = pblk_replace_blk(pblk, rblk, rlun, 1);
		if (ret)
			goto out;

		goto try;
	}
	spin_unlock(&rlun->lock);

	/* Prepare block for next write */
	if (block_is_full(pblk, rblk)) {
		ret = pblk_replace_blk(pblk, rblk, rlun, 0);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static void pblk_bio_free_pages(struct pblk *pblk, struct bio *bio, int off,
				int nr_pages)
{
		struct bio_vec bv;
		int i;

		WARN_ON(off + nr_pages != bio->bi_vcnt);

		bio_advance(bio, off * PBLK_EXPOSED_PAGE_SIZE);
		for (i = off; i < nr_pages + off; i++) {
			bv = bio->bi_io_vec[i];
			mempool_free(&bv.bv_page, pblk->page_pool);
		}
}

static int pblk_bio_add_pages(struct pblk *pblk, struct bio *bio, gfp_t flags,
			      int nr_pages)
{
	struct request_queue *q = pblk->dev->q;
	struct page *page;
	int ret;
	int i;

	for (i = 0; i < nr_pages; i++) {
		page = mempool_alloc(pblk->page_pool, flags);
		if (!page) {
			pr_err("pblk: could not alloc read page\n");
			goto err;
		}

		ret = bio_add_pc_page(q, bio, page,
						PBLK_EXPOSED_PAGE_SIZE, 0);
		if (ret != PBLK_EXPOSED_PAGE_SIZE) {
			pr_err("pblk: could not add page to bio\n");
			mempool_free(page, pblk->page_pool);
			goto err;
		}
	}

	return 0;

err:
	pblk_bio_free_pages(pblk, bio, 0, i - 1);
	return -1;
}

static void pblk_sync_buffer(struct pblk *pblk, struct pblk_addr p, int flags)
{
	struct pblk_block *rblk = p.rblk;
	u64 block_ppa;

	block_ppa = ppa_to_addr(p.ppa);
	WARN_ON(test_and_set_bit(block_ppa, rblk->sync_bitmap));

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->sync_writes);
	atomic_dec(&pblk->inflight_writes);
#endif

	/* If last page completed, then this is not a grown bad blodk */
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_gc(pblk, rblk, pblk_close_rblk_queue);
}

static void pblk_end_w_pad(struct pblk *pblk, struct nvm_rq *rqd,
							struct pblk_ctx *ctx)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;

	BUG_ON(c_ctx->nr_valid != 0);

	if (c_ctx->nr_padded > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);

	bio_put(rqd->bio);
	mempool_free(rqd, pblk->w_rq_pool);
}

static unsigned long pblk_end_w_bio(struct pblk *pblk, struct nvm_rq *rqd,
							struct pblk_ctx *ctx)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_w_ctx *w_ctx;
	struct bio *original_bio;
	int nr_entries = c_ctx->nr_valid;
	unsigned long ret;
	int i;

	for (i = 0; i < nr_entries; i++) {
		w_ctx = pblk_rb_w_ctx(&pblk->rwb, c_ctx->sentry + i);
		pblk_sync_buffer(pblk, w_ctx->ppa, w_ctx->flags);
		original_bio = w_ctx->bio;
		if (original_bio) {
			bio_endio(original_bio);
			w_ctx->bio = NULL;
		}
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_entries, &pblk->compl_writes);
#endif

	ret = pblk_rb_sync_advance(&pblk->rwb, nr_entries);

	if (nr_entries > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);

	bio_put(rqd->bio);
	mempool_free(rqd, pblk->w_rq_pool);

	return ret;
}

static unsigned long pblk_end_queued_w_bio(struct pblk *pblk,
			struct nvm_rq *rqd, struct pblk_ctx *ctx)
{
	list_del(&ctx->list);
	return pblk_end_w_bio(pblk, rqd, ctx);
}

static void pblk_compl_queue(struct pblk *pblk, struct nvm_rq *rqd,
							struct pblk_ctx *ctx)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_ctx *c, *r;
	unsigned long flags;
	unsigned long pos;

	pos = pblk_rb_sync_init(&pblk->rwb, &flags);

	if (c_ctx->sentry == pos) {
		pos = pblk_end_w_bio(pblk, rqd, ctx);

try:
		list_for_each_entry_safe(c, r, &pblk->compl_list, list) {
			rqd = nvm_rq_from_pdu(c);
			c_ctx = c->c_ctx;
			if (c_ctx->sentry == pos) {
				pos = pblk_end_queued_w_bio(pblk, rqd, c);
				goto try;
			}
		}
	} else {
		list_add_tail(&ctx->list, &pblk->compl_list);
	}

	pblk_rb_sync_end(&pblk->rwb, flags);
}

/*
 * pblk_end_w_fail -- deal with write failure
 * @pblk - pblk instance
 * @rqd - failed request
 *
 * When a write fails we assume for now that the flash block has grown bad.
 * Thus, we start a recovery mechanism to (in general terms):
 *  - Take block out of the active open block list
 *  - Complete the successful writes on the request
 *  - Remap failed writes to a new request
 *  - Move written data on grown bad block(s) to new block(s)
 *  - Mark grown bad block(s) as bad and return to media manager
 *
 *  pblk_end_w_fail is in charge of identifying the bad writes and mark the
 *  blocks associated to the write ppas as bad. JAVIER:: COMPLETE THIS.
 *
 *  This function assumes that ppas in rqd are in generic mode. This is,
 *  nvm_addr_to_generic_mode(dev, rqd) has been called.
 *
 *  TODO: Depending on the type of memory, try write retry
 */
static void pblk_end_w_fail(struct pblk *pblk, struct nvm_rq *rqd)
{
	void *comp_bits = &rqd->ppa_status;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	struct pblk_rec_ctx *recovery;
	struct ppa_addr ppa, prev_ppa;
	unsigned int c_entries;
	int nr_ppas = rqd->nr_ppas;
	int bit, mod;
	int ret;

	/* The last page of a block contains recovery metadata, if a block
	 * becomes bad when writing this page, there is no need to recover what
	 * is being written; this metadata is generated in a per-block basis.
	 * This block is on its way to being closed. Mark as bad and trigger
	 * recovery
	 */
	if (ctx->flags & PBLK_IOTYPE_CLOSE_BLK) {
		struct pblk_compl_close_ctx *c_ctx = ctx->c_ctx;

		pblk_run_recovery(pblk, c_ctx->rblk);
		pblk_end_close_blk_bio(pblk, rqd, 0);
		return;
	}

	/* look up blocks and mark them as bad
	 * TODO: RECOVERY HERE TOO
	 * */
	if (nr_ppas == 1) {
		return;
	}

	recovery = mempool_alloc(pblk->rec_pool, GFP_ATOMIC);
	if (!recovery) {
		pr_err("pblk: could not allocate recovery context\n");
		return;
	}
	INIT_LIST_HEAD(&recovery->failed);

	c_entries = find_next_bit(comp_bits, nr_ppas, 0);

	/* Assume that all writes to a block have either succeeded or failed */
	div_u64_rem(c_entries, pblk->min_write_pgs, &mod);
	BUG_ON(mod);

	/* Replace all grown bad blocks on RR mapping scheme, mark them as bad
	 * and return them to the media manager.
	 */
	ppa_set_empty(&prev_ppa);
	bit = -1;
	while ((bit = find_next_bit(comp_bits, nr_ppas, bit + 1)) < nr_ppas) {
		if (bit > c_ctx->nr_valid)
			goto out;

		ppa = rqd->ppa_list[bit];

		entry = pblk_rb_sync_scan_entry(&pblk->rwb, &ppa);
		if (!entry) {
			pr_err("pblk: could not scan entry on write failure\n");
			continue;
		}
		w_ctx = &entry->w_ctx;

		/* The list is filled first and emptied afterwards. No need for
		 * protecting it with a lock
		 */
		list_add_tail(&entry->index, &recovery->failed);

		if (ppa_cmp_blk(ppa, prev_ppa))
			continue;

		prev_ppa.ppa = ppa.ppa;

		pblk_run_recovery(pblk, w_ctx->ppa.rblk);
	}

out:
	ret = pblk_setup_rec_end_rq(pblk, ctx, recovery, comp_bits, c_entries);
	if (ret)
		pr_err("pblk: could not recover from write failure\n");

	pblk_compl_queue(pblk, rqd, ctx);
}

static void pblk_end_io_write(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct pblk_ctx *ctx;

	if (rqd->error == NVM_RSP_ERR_FAILWRITE)
		return pblk_end_w_fail(pblk, rqd);

	ctx = pblk_set_ctx(pblk, rqd);

	if (ctx->flags & PBLK_IOTYPE_CLOSE_BLK)
		return pblk_end_close_blk_bio(pblk, rqd, 1);

	if (ctx->flags & PBLK_IOTYPE_PAD)
		return pblk_end_w_pad(pblk, rqd, ctx);

	pblk_compl_queue(pblk, rqd, ctx);
	pblk_write_kick(pblk);
}

static void pblk_end_io_read(struct pblk *pblk, struct nvm_rq *rqd,
							uint8_t nr_secs)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;

	if (r_ctx->flags & PBLK_IOTYPE_TEST)
		return;

	if (nr_secs > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);

	if (r_ctx->flags & PBLK_IOTYPE_SYNC)
		return;

	bio_put(bio);
	mempool_free(rqd, pblk->r_rq_pool);

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_secs, &pblk->sync_reads);
	atomic_sub(nr_secs, &pblk->inflight_reads);
#endif
}

void pblk_end_io(struct nvm_rq *rqd)
{
	struct pblk *pblk = container_of(rqd->ins, struct pblk, instance);
	uint8_t nr_secs = rqd->nr_ppas;

	if (bio_data_dir(rqd->bio) == READ)
		pblk_end_io_read(pblk, rqd, nr_secs);
	else
		pblk_end_io_write(pblk, rqd);
}

/*
 * Copy data from current bio to write buffer. This if necessary to guarantee
 * that (i) writes to the media at issued at the right granurality and (ii) that
 * memory-specific constrains are respected (e.g., TLC memories need to write
 * upper, medium and lower pages to guarantee that data has been persisted).
 *
 * return: 1 if bio has been written to buffer, 0 otherwise.
 */
static int pblk_write_to_cache(struct pblk *pblk, struct bio *bio,
				 unsigned long flags, unsigned int nr_entries,
				 int *ret_val)
{
	sector_t laddr = pblk_get_laddr(bio);
	struct pblk_w_ctx w_ctx;
	struct ppa_addr ppa;
	void *data;
	struct bio *b = NULL;
	unsigned long pos;
	unsigned int i;

	BUG_ON(!bio_has_data(bio));

	pblk_rb_write_init(&pblk->rwb);

	if (pblk_rb_space(&pblk->rwb) < nr_entries)
		goto rollback;

	if (pblk_rb_update_l2p(&pblk->rwb, nr_entries))
		goto rollback;

	pos = pblk_rb_write_pos(&pblk->rwb);

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		b = bio;
		*ret_val = NVM_IO_OK;
	} else {
		b = NULL;
		*ret_val = NVM_IO_DONE;
	}

	for (i = 0; i < nr_entries; i++) {
		w_ctx.bio = b;
		w_ctx.lba = laddr + i;
		w_ctx.flags = flags;
		w_ctx.priv = NULL;
		ppa_set_empty(&w_ctx.ppa.ppa);

		data = bio_data(bio);
		if (pblk_rb_write_entry(&pblk->rwb, data, w_ctx, pos + i))
			goto rollback;

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

	for (i = 0; i < nr_entries; i++) {
		ppa = pblk_cacheline_to_ppa(
					pblk_rb_wrap_pos(&pblk->rwb, pos + i));
		pblk_update_map(pblk, laddr + i, NULL, ppa);
	}

	/* Update mapping table with the write buffer cachelines and commit
	 * write transaction. This enables atomic rollback.
	 */
	pblk_rb_write_commit(&pblk->rwb, nr_entries);
	return 1;

rollback:
	pblk_rb_write_rollback(&pblk->rwb);
	return 0;
}

static int pblk_buffer_write(struct pblk *pblk, struct bio *bio,
							unsigned long flags)
{
	uint8_t nr_secs = pblk_get_pages(bio);
	int ret = NVM_IO_DONE;

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
#ifdef CONFIG_NVM_DEBUG
		atomic_inc(&pblk->nr_flush);
#endif
		if (!bio_has_data(bio)) {
			if (pblk_rb_sync_point_set(&pblk->rwb, bio))
				ret = NVM_IO_OK;
			pblk_write_kick(pblk);
			goto out;
		}
	}

	if (!pblk_write_to_cache(pblk, bio, flags, nr_secs, &ret))
		return NVM_IO_REQUEUE;

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_secs, &pblk->inflight_writes);
	atomic_add(nr_secs, &pblk->req_writes);
#endif

	/* Use count as a heuristic for setting up a job in workqueue */
	if (pblk_rb_count(&pblk->rwb) >= pblk->min_write_pgs)
		pblk_write_kick(pblk);

out:
	return ret;
}

int pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
			   struct ppa_addr ppa)
{
	u64 cacheline;
	int read = 0;

	cacheline = nvm_addr_to_cacheline(ppa);
	if (!pblk_rb_copy_to_bio(&pblk->rwb, bio, cacheline))
		goto out;

	read = 1;
out:
	return read;
}

static int pblk_try_read_from_cache(struct pblk *pblk, struct bio *bio,
							struct pblk_addr *addr)
{
	/* The write thread commits the changes to the buffer once the l2p table
	 * has been updated. In this way, if the address read from the l2p table
	 * points to a cacheline, the lba lock guarantees that the entry is not
	 * going to be updated by new writes
	 */
	if (!nvm_addr_in_cache(addr->ppa))
		return 0;

	return pblk_read_from_cache(pblk, bio, addr->ppa);
}

static int pblk_read_ppalist_rq(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, unsigned long flags, int nr_secs,
			unsigned long *read_bitmap)
{
	sector_t laddr = pblk_get_laddr(bio);
	int advanced_bio = 0;
	int i, j = 0;
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];

	BUG_ON(!(laddr >= 0 && laddr + nr_secs < pblk->nr_secs));

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++)
		ppas[i] = pblk->trans_map[laddr + i].ppa;
	spin_unlock(&pblk->trans_lock);

	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr *p = &ppas[i];

		if (ppa_empty(*p)) {
			WARN_ON(test_and_set_bit(i, read_bitmap));
			continue;
		}

		/* Try to read from write buffer. Those addresses that cannot be
		 * read from the write buffer are sequentially added to the ppa
		 * list, which will later on be used to submit an I/O to the
		 * device to retrieve data.
		 */
		if (nvm_addr_in_cache(*p)) {
			WARN_ON(test_and_set_bit(i, read_bitmap));
			if (unlikely(!advanced_bio)) {
				/* This is at least a partially filled bio,
				 * advance it to copy data to the right place.
				 * We will deal with partial bios later on.
				 */
				bio_advance(bio, i * PBLK_EXPOSED_PAGE_SIZE);
				advanced_bio = 1;
			}
			pblk_read_from_cache(pblk, bio, *p);
		} else {
			/* Fill ppa_list with the sectors that cannot be
			 * read from cache
			 */
			rqd->ppa_list[j] = *p;
			j++;
		}

		if (advanced_bio)
			bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
		atomic_add(nr_secs, &pblk->inflight_reads);
#endif

	return NVM_IO_OK;
}

int pblk_read_rq(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
		 sector_t laddr, unsigned long flags,
		 unsigned long *read_bitmap)
{
	/* int is_gc = *flags & PBLK_IOTYPE_GC; */
	struct pblk_addr *gp;

	if (laddr == ADDR_EMPTY) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		goto done;
	}

	BUG_ON(!(laddr >= 0 && laddr < pblk->nr_secs));

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];
	spin_unlock(&pblk->trans_lock);

	if (ppa_empty(gp->ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		goto done;
	}

	if (pblk_try_read_from_cache(pblk, bio, gp)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		goto done;
	}

	rqd->ppa_addr = gp->ppa;

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_reads);
#endif

	return NVM_IO_OK;

done:
	return NVM_IO_DONE;
}

int pblk_submit_read_io(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, unsigned long flags)
{
	int err;

/*
	switch(dev->plane_mode) {
	case NVM_PLANE_QUAD:
		if (rqd->nr_ppas > 2)
			rqd->flags |= NVM_IO_QUAD_ACCESS;
		else if (rqd->nr_ppas > 1)
			rqd->flags |= NVM_IO_DUAL_ACCESS;
		else
			rqd->flags |= NVM_IO_SNGL_ACCESS;
		break;
	case NVM_PLANE_DOUBLE:
		if (rqd->nr_ppas > 1)
			rqd->flags |= NVM_IO_DUAL_ACCESS;
		else
			rqd->flags |= NVM_IO_SNGL_ACCESS;
		break;
	case NVM_PLANE_SINGLE:
		rqd->flags |= NVM_IO_SNGL_ACCESS;
		break;
	default:
		pr_err("pblk: invalid plane configuration\n");
		return NVM_IO_ERR;
	}
*/
	rqd->flags |= NVM_IO_SNGL_ACCESS;
	rqd->flags |= NVM_IO_SUSPEND;

	err = nvm_submit_io(pblk->dev, rqd);
	if (err) {
		pr_err("pblk: I/O submission failed: %d\n", err);
		bio_put(bio);
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

int pblk_fill_partial_read_bio(struct pblk *pblk, struct bio *bio,
			       unsigned long *read_bitmap, struct nvm_rq *rqd,
			       uint8_t nr_secs)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *new_bio;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int nr_holes = nr_secs - bitmap_weight(read_bitmap, nr_secs);
	int hole;
	int i;
	int ret;
	uint16_t flags;
	DECLARE_COMPLETION_ONSTACK(wait);
#ifdef CONFIG_NVM_DEBUG
	struct ppa_addr *ppa_list;
#endif

	new_bio = bio_alloc(GFP_KERNEL, nr_holes);
	if (!new_bio) {
		pr_err("pblk: could not alloc read bio\n");
		return NVM_IO_ERR;
	}

	if (pblk_bio_add_pages(pblk, new_bio, GFP_KERNEL, nr_holes)) {
		printk(KERN_CRIT "WTF\n");
		bio_put(bio);
		goto err;
	}

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
		goto err;
	}

	new_bio->bi_iter.bi_sector = 0; /* artificial bio */
	new_bio->bi_rw = READ;
	new_bio->bi_private = &wait;
	new_bio->bi_end_io = pblk_end_sync_bio;

	flags = r_ctx->flags;
	r_ctx->flags |= PBLK_IOTYPE_TEST;
	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;

#ifdef CONFIG_NVM_DEBUG
	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
	if (nvm_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
		BUG_ON(1);
		/* WARN_ON(1); */
#endif

	ret = pblk_submit_read_io(pblk, new_bio, rqd, r_ctx->flags);
	wait_for_completion_io(&wait);

	if (ret || new_bio->bi_error)
		goto err;
	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_secs);
	do {
		src_bv = new_bio->bi_io_vec[i];
		dst_bv = bio->bi_io_vec[hole];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

		mempool_free(&src_bv.bv_page, pblk->page_pool);

		i++;
		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_secs);

	bio_put(new_bio);

	/* Complete the original bio and associated request */
	r_ctx->flags = flags;
	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;

	bio_endio(bio);
	pblk_end_io(rqd);
	return NVM_IO_OK;

err:
	/* Free allocated pages in new bio */
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);
	bio_endio(new_bio);
	return NVM_IO_ERR;
}

static int __pblk_submit_read(struct pblk *pblk, struct bio *bio,
				struct nvm_rq *rqd, unsigned long flags)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	unsigned long read_bitmap; /* Max 64 ppas per request */
	uint8_t nr_secs = pblk_get_pages(bio);
	int ret;

	bitmap_zero(&read_bitmap, nr_secs);

	rqd->meta_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
							&rqd->dma_meta_list);
	if (!rqd->meta_list) {
		pr_err("pblk: not able to allocate metadata list\n");
		return NVM_IO_ERR;
	}

	if (nr_secs != bio->bi_vcnt)
		return NVM_IO_ERR;

	if (nr_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
						&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			ret = NVM_IO_ERR;
			goto fail_meta_free;
		}

		ret = pblk_read_ppalist_rq(pblk, bio, rqd, flags, nr_secs,
								&read_bitmap);
		if (ret)
			goto fail_ppa_free;
	} else {
		sector_t laddr = pblk_get_laddr(bio);

		ret = pblk_read_rq(pblk, bio, rqd, laddr, flags, &read_bitmap);
		if (ret)
			goto fail_meta_free;
	}

	bio_get(bio);
	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = nr_secs;
	r_ctx->flags = flags;

	if (bitmap_full(&read_bitmap, nr_secs)) {
		bio_endio(bio);
		pblk_end_io(rqd);
		return NVM_IO_OK;
	} else if (bitmap_empty(&read_bitmap, nr_secs)) {
#ifdef CONFIG_NVM_DEBUG
		struct ppa_addr *ppa_list;

		ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
		if (nvm_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
			BUG_ON(1);
			/* WARN_ON(1); */
#endif
		ret = pblk_submit_read_io(pblk, bio, rqd, flags);
		if (ret) {
			pr_err("pblk: read IO submission failed\n");
			goto fail_ppa_free;
		}

		return NVM_IO_OK;
	}

	/* The read bio request could be partially filled by the write buffer,
	 * but there are some holes that need to be read from the drive.
	 */
	ret = pblk_fill_partial_read_bio(pblk, bio, &read_bitmap, rqd,
								nr_secs);
	if (ret) {
		pr_err("pblk: failed to perform partial read\n");
		goto fail_ppa_free;
	}

	return NVM_IO_OK;

fail_ppa_free:
	if ((nr_secs > 1) && (!(flags & PBLK_IOTYPE_GC)))
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);
fail_meta_free:
	nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);
	return ret;
}

static int pblk_submit_read(struct pblk *pblk, struct bio *bio,
							unsigned long flags)
{
	struct nvm_rq *rqd;
	int ret;

	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd) {
		pr_err_ratelimited("pblk: not able to queue bio.");
		bio_io_error(bio);
		return NVM_IO_ERR;
	}
	memset(rqd, 0, pblk_r_rq_size);

	ret = __pblk_submit_read(pblk, bio, rqd, flags);
	if (ret)
		mempool_free(rqd, pblk->r_rq_pool);

	return ret;
}

static int pblk_submit_io(struct pblk *pblk, struct bio *bio,
							unsigned long flags)
{
	int bio_size = bio_sectors(bio) << 9;
	int is_flush = (bio->bi_rw & (REQ_FLUSH | REQ_FUA));

	if ((bio_size < pblk->dev->sec_size) && (!is_flush))
		return NVM_IO_ERR;
	else if (bio_size > pblk->dev->max_rq_size)
		return NVM_IO_ERR;

	if (bio_rw(bio) == READ)
		return pblk_submit_read(pblk, bio, flags);

	return pblk_buffer_write(pblk, bio, flags);
}

static blk_qc_t pblk_make_rq(struct request_queue *q, struct bio *bio)
{
	struct pblk *pblk = q->queuedata;
	int err;

	if (bio->bi_rw & REQ_DISCARD) {
		pblk_discard(pblk, bio);
		if (!(bio->bi_rw & (REQ_FLUSH | REQ_FUA)))
			return BLK_QC_T_NONE;
	}

	err = pblk_submit_io(pblk, bio, PBLK_IOTYPE_NONE);
	switch (err) {
	case NVM_IO_OK:
		return BLK_QC_T_NONE;
	case NVM_IO_ERR:
		bio_io_error(bio);
		break;
	case NVM_IO_DONE:
		bio_endio(bio);
		break;
	case NVM_IO_REQUEUE:
		spin_lock(&pblk->bio_lock);
		bio_list_add(&pblk->requeue_bios, bio);
		spin_unlock(&pblk->bio_lock);
		queue_work(pblk->kgc_wq, &pblk->ws_requeue);
		break;
	}

	return BLK_QC_T_NONE;
}

int pblk_alloc_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
		      struct pblk_ctx *ctx, unsigned int nr_secs)
{
	struct nvm_dev *dev = pblk->dev;

	/* Setup write request */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = nr_secs;

	/* We work at a page granurality to meet controller constrains, but we
	 * map at a sector granurality since the l2p entries represent 4KB
	 */
	switch(dev->plane_mode) {
	case NVM_PLANE_QUAD:
		rqd->flags |= NVM_IO_QUAD_ACCESS;
		break;
	case NVM_PLANE_DOUBLE:
		rqd->flags |= NVM_IO_DUAL_ACCESS;
		break;
	case NVM_PLANE_SINGLE:
		rqd->flags |= NVM_IO_SNGL_ACCESS;
		break;
	default:
		pr_err("pblk: invalid plane configuration\n");
		return -EINVAL;
	}

	rqd->meta_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
							&rqd->dma_meta_list);
	if (!rqd->meta_list) {
		pr_err("pblk: not able to allocate metadata list\n");
		return -ENOMEM;
	}

	if (unlikely(nr_secs == 1))
		return 0;

	rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
							&rqd->dma_ppa_list);
	if (!rqd->ppa_list) {
		nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);
		pr_err("pblk: not able to allocate ppa list\n");
		return -ENOMEM;
	}

	return 0;
}

int pblk_setup_w_single(struct pblk *pblk, struct nvm_rq *rqd,
			struct pblk_ctx *ctx, struct pblk_sec_meta *meta)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	int ret;

	/*
	 * Single sector path - this path is highly improbable since
	 * controllers typically deal with multi-sector and multi-plane
	 * pages. This path is though useful for testing on QEMU
	 */
	BUG_ON(pblk->dev->sec_per_pl != 1);

	ret = pblk_map_rr_page(pblk, c_ctx->sentry, &rqd->ppa_addr,
							&meta[0], 1, 1);
	if (ret) {
		/*
		 * TODO:  There is no more available pages, we need to
		 * recover. Probably a requeue of the bio is enough.
		 */
		BUG_ON(1);
	}

	return ret;
}

int pblk_setup_w_multi(struct pblk *pblk, struct nvm_rq *rqd,
		       struct pblk_ctx *ctx, struct pblk_sec_meta *meta,
		       unsigned int valid_secs, int off)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	int min = pblk->min_write_pgs;
	int ret = 0;

	ret = pblk_map_rr_page(pblk, c_ctx->sentry + off,
					&rqd->ppa_list[off],
					&meta[off], min, valid_secs);
	if (ret) {
		/*
		 * TODO:  There is no more available pages, we need to
		 * recover. Probably a requeue of the bio is enough.
		 */
		BUG_ON(1);
	}

	return ret;
}

static int pblk_setup_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
						struct pblk_ctx *ctx)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	unsigned int nr_secs = valid_secs + padded_secs;
	struct pblk_sec_meta *meta;
	unsigned int setup_secs;
	int min = pblk->min_write_pgs;
	int i;
	int ret = 0;

	ret = pblk_alloc_w_rq(pblk, rqd, ctx, nr_secs);
	if (ret)
		goto out;

	meta = rqd->meta_list;

	if (unlikely(nr_secs == 1)) {
		BUG_ON(padded_secs != 0);
		ret = pblk_setup_w_single(pblk, rqd, ctx, meta);
		goto out;
	}

	for (i = 0; i < nr_secs; i += min) {
		setup_secs = (i + min > valid_secs) ?
						(valid_secs % min) : min;
		ret = pblk_setup_w_multi(pblk, rqd, ctx, meta, setup_secs, i);
	}

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(dev, rqd->ppa_list, rqd->nr_ppas))
		BUG_ON(1);
		/* WARN_ON(1); */
#endif

out:
	return ret;
}

static int pblk_setup_pad_rq(struct pblk *pblk, struct pblk_block *rblk,
				struct nvm_rq *rqd, struct pblk_ctx *ctx)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	struct pblk_lun *rlun = rblk->rlun;
	unsigned int nr_secs = valid_secs + padded_secs;
	struct pblk_sec_meta *meta;
	int min = pblk->min_write_pgs;
	int i;
	int ret = 0;

	ret = pblk_alloc_w_rq(pblk, rqd, ctx, nr_secs);
	if (ret)
		goto out;

	meta = rqd->meta_list;

	if (unlikely(nr_secs == 1)) {
		/*
		 * Single sector path - this path is highly improbable since
		 * controllers typically deal with multi-sector and multi-plane
		 * pages. This path is though useful for testing on QEMU
		 */
		BUG_ON(dev->sec_per_pl != 1);
		BUG_ON(padded_secs != 0);

		spin_lock(&rlun->lock);
		ret = pblk_map_page(pblk, rblk, c_ctx->sentry, &rqd->ppa_addr,
								&meta[0], 1, 0);
		spin_unlock(&rlun->lock);

		if (ret) {
			/*
			 * TODO:  There is no more available pages, we need to
			 * recover. Probably a requeue of the bio is enough.
			 */
			BUG_ON(1);
		}

		goto out;
	}

	for (i = 0; i < nr_secs; i += min) {
		spin_lock(&rlun->lock);
		ret = pblk_map_page(pblk, rblk, c_ctx->sentry + i,
						&rqd->ppa_list[i],
						&meta[i], min, 0);
		spin_unlock(&rlun->lock);

		if (ret) {
			/*
			 * TODO:  There is no more available pages, we need to
			 * recover. Probably a requeue of the bio is enough.
			 */
			BUG_ON(1);
		}
	}

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(dev, rqd->ppa_list, rqd->nr_ppas))
		BUG_ON(1);
		/* WARN_ON(1); */
#endif

out:
	return ret;
}

/*
 * pblk_submit_write -- thread to submit buffered writes to device
 *
 * The writer respects page size constrains defined by the device and will try
 * to send as many pages in a single I/O as supported by the device.
 *
 */
static void pblk_submit_write(struct work_struct *work)
{
	struct pblk *pblk = container_of(work, struct pblk, ws_writer);
	struct nvm_dev *dev = pblk->dev;
	struct bio *bio;
	struct nvm_rq *rqd;
	struct pblk_ctx *ctx;
	struct pblk_compl_ctx *c_ctx;
	unsigned int pgs_read;
	unsigned int secs_avail, secs_to_sync, secs_to_flush = 0;
	unsigned long sync_point;
	int err;

	rqd = mempool_alloc(pblk->w_rq_pool, GFP_KERNEL);
	if (!rqd) {
		pr_err("pblk: not able to create write req.\n");
		return;
	}
	memset(rqd, 0, pblk_w_rq_size);
	ctx = pblk_set_ctx(pblk, rqd);
	c_ctx = ctx->c_ctx;

	bio = bio_alloc(GFP_KERNEL, pblk->max_write_pgs);
	if (!bio) {
		pr_err("pblk: not able to create write bio\n");
		goto fail_rqd;
	}

	/* Count available entries on rb, and lock reader */
	secs_avail = pblk_rb_count_init(&pblk->rwb);
	if (!secs_avail)
		goto fail_bio;

	secs_to_flush = pblk_rb_sync_point_count(&pblk->rwb);
	secs_to_sync = pblk_calc_secs_to_sync(pblk, secs_avail, secs_to_flush);
	if (secs_to_sync < 0) {
		pr_err("pblk: bad buffer sync calculation\n");
		goto end_rollback;
	}

	if (!secs_to_sync)
		goto end_rollback;

	pgs_read = pblk_rb_read_to_bio(&pblk->rwb, bio, ctx, secs_to_sync,
							&sync_point);
	if (!pgs_read)
		goto fail_sync;

	if (secs_to_flush <= secs_to_sync)
		pblk_rb_sync_point_reset(&pblk->rwb, sync_point);

	pblk_rb_read_commit(&pblk->rwb, pgs_read);

	if (c_ctx->nr_padded)
		if (pblk_bio_add_pages(pblk, bio, GFP_KERNEL, c_ctx->nr_padded))
			goto fail_sync;

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio->bi_rw = WRITE;
	rqd->bio = bio;

	/* Assign lbas to ppas and populate request structure */
	err = pblk_setup_w_rq(pblk, rqd, ctx);
	if (err) {
		pr_err("pblk: could not setup write request\n");
		goto fail_free_bio;
	}

	err = nvm_submit_io(dev, rqd);
	if (err) {
		pr_err("pblk: I/O submission failed: %d\n", err);
		goto fail_free_bio;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(secs_to_sync, &pblk->sub_writes);
#endif

	return;

fail_free_bio:
	if (c_ctx->nr_padded)
		pblk_bio_free_pages(pblk, bio, secs_to_sync, c_ctx->nr_padded);
fail_sync:
	/* Fail is probably caused by a locked lba - kick the queue to avoid a
	 * deadlock in the case that no new I/Os are coming in.
	 */
	pblk_write_kick(pblk);
end_rollback:
	pblk_rb_read_rollback(&pblk->rwb);
fail_bio:
	bio_put(bio);
fail_rqd:
	mempool_free(rqd, pblk->w_rq_pool);
}

static void pblk_requeue(struct work_struct *work)
{
	struct pblk *pblk = container_of(work, struct pblk, ws_requeue);
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock(&pblk->bio_lock);
	bio_list_merge(&bios, &pblk->requeue_bios);
	bio_list_init(&pblk->requeue_bios);
	spin_unlock(&pblk->bio_lock);

	while ((bio = bio_list_pop(&bios)))
		pblk_make_rq(pblk->disk->queue, bio);
}

static void pblk_gc_free(struct pblk *pblk)
{
	if (pblk->krqd_wq)
		destroy_workqueue(pblk->krqd_wq);

	if (pblk->kgc_wq)
		destroy_workqueue(pblk->kgc_wq);
}

static int pblk_gc_init(struct pblk *pblk)
{
	pblk->krqd_wq = alloc_workqueue("pblk-lun", WQ_MEM_RECLAIM | WQ_UNBOUND,
								pblk->nr_luns);
	if (!pblk->krqd_wq)
		return -ENOMEM;

	pblk->kgc_wq = alloc_workqueue("pblk-bg", WQ_MEM_RECLAIM, 1);
	if (!pblk->kgc_wq)
		return -ENOMEM;

	setup_timer(&pblk->gc_timer, pblk_gc_timer, (unsigned long)pblk);

	return 0;
}

static void pblk_map_free(struct pblk *pblk)
{
	vfree(pblk->trans_map);
}

static int pblk_map_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	sector_t i;
	u64 slba;

	slba = pblk->soffset >> (ilog2(dev->sec_size) - 9);

	pblk->trans_map = vzalloc(sizeof(struct pblk_addr) * pblk->nr_secs);
	if (!pblk->trans_map)
		return -ENOMEM;

	for (i = 0; i < pblk->nr_secs; i++) {
		struct pblk_addr *p = &pblk->trans_map[i];
		p->rblk = NULL;
		ppa_set_empty(&p->ppa);
	}

	return 0;
}

static void pblk_rwb_free(struct pblk *pblk)
{
	vfree(pblk_rb_data_ref(&pblk->rwb));
	vfree(pblk_rb_entries_ref(&pblk->rwb));
}

static int pblk_rwb_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_rb_entry *entries;
	void *data_buffer;
	unsigned long nr_entries, data_size;
	unsigned power_size, power_seg_sz, grace_area_sz;

	/*
	 * pblk write buffer characteristics:
	 *  - It must be able to hold one entire flash block from each device
	 *  LUN configured in the target.
	 *  - It must respect a grace area corresponding to the actual memory
	 *  constrains so that the memory is correctly programmed. For example,
	 *  in TLC NAND memories there should be space enough so that each block
	 *  present in the buffer can hold the upper, middle, and lower page so
	 *  that the NAND can be correctly programmed.
	 *  - It is not necessary that a whole flash block is maintained in
	 *  memory before the last sector of the block is persisted in the NAND.
	 *  If a block becomes bad while it is being programmed, already written
	 *  pages can be read, as long as the write constrains are being met,
	 *  e.g., programming the three mentioned pages in TLC memories.
	 *  - Each entry of the buffer holds a pointer to the actual data on
	 *  that entry and a pointer to metadata associated to the entry.
	 */
	nr_entries = pblk->nr_luns * dev->sec_per_blk;
	data_size = nr_entries * dev->sec_size;

	data_buffer = vmalloc(data_size);
	if (!data_buffer)
		return -ENOMEM;

	entries = vmalloc(nr_entries * sizeof(struct pblk_rb_entry));
	if (!entries) {
		vfree(pblk->rwb.data);
		return -ENOMEM;
	}

	/* Assume no grace area for now */
	grace_area_sz = 0;
	power_size = get_count_order(nr_entries);
	power_seg_sz = get_count_order(dev->sec_size);

	return pblk_rb_init(&pblk->rwb, entries, data_buffer, grace_area_sz,
						power_size, power_seg_sz);
}

/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int pblk_core_init(struct pblk *pblk)
{
	down_write(&pblk_lock);
	if (!pblk_gcb_cache) {
		pblk_gcb_cache = kmem_cache_create("pblk_gcb",
				sizeof(struct pblk_block_gc), 0, 0, NULL);
		if (!pblk_gcb_cache) {
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_rec_cache = kmem_cache_create("pblk_rec",
				sizeof(struct pblk_rec_ctx), 0, 0, NULL);
		if (!pblk_rec_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_r_rq_size = sizeof(struct nvm_rq) +
				sizeof(struct pblk_r_ctx);
		pblk_r_rq_cache = kmem_cache_create("pblk_r_rq", pblk_r_rq_size,
				0, 0, NULL);
		if (!pblk_r_rq_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			kmem_cache_destroy(pblk_rec_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_w_rq_size = sizeof(struct nvm_rq) +
				sizeof(struct pblk_ctx) +
				sizeof(struct pblk_compl_ctx);
		pblk_w_rq_cache = kmem_cache_create("pblk_w_rq", pblk_w_rq_size,
				0, 0, NULL);
		if (!pblk_w_rq_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			kmem_cache_destroy(pblk_rec_cache);
			kmem_cache_destroy(pblk_r_rq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}
	}
	up_write(&pblk_lock);

	pblk->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!pblk->page_pool)
		return -ENOMEM;

	pblk->gcb_pool = mempool_create_slab_pool(pblk->dev->nr_luns,
								pblk_gcb_cache);
	if (!pblk->gcb_pool)
		goto free_page_pool;

	pblk->rec_pool = mempool_create_slab_pool(pblk->dev->nr_luns,
								pblk_rec_cache);
	if (!pblk->rec_pool)
		goto free_gcb_pool;

	pblk->r_rq_pool = mempool_create_slab_pool(64, pblk_r_rq_cache);
	if (!pblk->r_rq_pool)
		goto free_rec_pool;

	pblk->w_rq_pool = mempool_create_slab_pool(16, pblk_w_rq_cache);
	if (!pblk->w_rq_pool)
		goto free_r_rq_pool;

	pblk->kw_wq = alloc_workqueue("pblk-writer",
				WQ_MEM_RECLAIM | WQ_UNBOUND, pblk->nr_luns);
	if (!pblk->kw_wq)
		goto free_w_rq_pool;

	/* Init write buffer */
	if (pblk_rwb_init(pblk))
		goto free_kw_wq;

	INIT_LIST_HEAD(&pblk->compl_list);

	return 0;

free_kw_wq:
	destroy_workqueue(pblk->kw_wq);
free_w_rq_pool:
	mempool_destroy(pblk->w_rq_pool);
free_r_rq_pool:
	mempool_destroy(pblk->r_rq_pool);
free_rec_pool:
	mempool_destroy(pblk->rec_pool);
free_gcb_pool:
	mempool_destroy(pblk->gcb_pool);
free_page_pool:
	mempool_destroy(pblk->page_pool);

	return -ENOMEM;

}

static void pblk_core_free(struct pblk *pblk)
{
	if (pblk->kw_wq)
		destroy_workqueue(pblk->kw_wq);

	mempool_destroy(pblk->page_pool);
	mempool_destroy(pblk->gcb_pool);
	mempool_destroy(pblk->r_rq_pool);
	mempool_destroy(pblk->w_rq_pool);
}

static void pblk_luns_free(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun;
	struct pblk_lun *rlun;
	int i;

	if (!pblk->luns)
		return;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		lun = rlun->parent;
		if (!lun)
			break;
		dev->mt->release_lun(dev, lun->id);
		vfree(rlun->blocks);
	}

	kfree(pblk->luns);
}

static int pblk_luns_init(struct pblk *pblk, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_lun *rlun;
	int i, j, mod, ret = -EINVAL;

	pblk->nr_blk_dsecs = dev->sec_per_blk - dev->sec_per_pl;
	pblk->min_write_pgs = dev->sec_per_pl * (dev->sec_size / PAGE_SIZE);
	/* assume max_phys_sect % dev->min_write_pgs == 0 */
	pblk->max_write_pgs = dev->ops->max_phys_sect;

	if (pblk->max_write_pgs > PBLK_MAX_REQ_ADDRS) {
		pr_err("pblk: cannot support device max_phys_sect\n");
		return -EINVAL;
	}

	div_u64_rem(dev->sec_per_blk, pblk->min_write_pgs, &mod);
	if (mod) {
		pr_err("pblk: bad configuration of sectors/pages\n");
		return -EINVAL;
	}

	pblk->luns = kcalloc(pblk->nr_luns, sizeof(struct pblk_lun),
								GFP_KERNEL);
	if (!pblk->luns)
		return -ENOMEM;

	/* 1:1 mapping */
	for (i = 0; i < pblk->nr_luns; i++) {
		/* Align lun list to the channel each lun belongs to */
		int ch =  ((lun_begin + i) % pblk->dev->nr_chnls);
		int lun_raw =  ((lun_begin + i) / pblk->dev->nr_chnls);
		int lunid =  lun_raw + ch * pblk->dev->luns_per_chnl;
		struct nvm_lun *lun;

		if (dev->mt->reserve_lun(dev, lunid)) {
			pr_err("pblk: lun %u is already allocated\n", lunid);
			goto err;
		}

		lun = dev->mt->get_lun(dev, lunid);
		if (!lun)
			goto err;

		rlun = &pblk->luns[i];
		rlun->parent = lun;
		rlun->blocks = vzalloc(sizeof(struct pblk_block) *
						pblk->dev->blks_per_lun);
		if (!rlun->blocks) {
			ret = -ENOMEM;
			goto err;
		}

		for (j = 0; j < pblk->dev->blks_per_lun; j++) {
			struct pblk_block *rblk = &rlun->blocks[j];
			struct nvm_block *blk = &lun->blocks[j];

			rblk->parent = blk;
			rblk->rlun = rlun;
			INIT_LIST_HEAD(&rblk->prio);
			spin_lock_init(&rblk->lock);
		}

		rlun->pblk = pblk;
		INIT_LIST_HEAD(&rlun->prio_list);
		INIT_LIST_HEAD(&rlun->open_list);
		INIT_LIST_HEAD(&rlun->closed_list);
		INIT_LIST_HEAD(&rlun->bb_list);

		rlun->nr_bad_blocks = 0;

		INIT_WORK(&rlun->ws_gc, pblk_lun_gc);
		/* INIT_WORK(&rlun->ws_prov, pblk_lun_prov); */

		spin_lock_init(&rlun->lock);
		spin_lock_init(&rlun->lock_lists);

		pblk->total_blocks += dev->blks_per_lun;
		pblk->nr_secs += dev->sec_per_lun;

	}

	return 0;
err:
	return ret;
}

/* returns 0 on success and stores the beginning address in *begin */
static int pblk_area_init(struct pblk *pblk, sector_t *begin)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvmm_type *mt = dev->mt;
	sector_t size = pblk->nr_secs * dev->sec_size;

	size >>= 9;

	return mt->get_area(dev, begin, size);
}

static void pblk_area_free(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvmm_type *mt = dev->mt;

	mt->put_area(dev, pblk->soffset);
}

static void pblk_free(struct pblk *pblk)
{
	pblk_gc_free(pblk);
	pblk_map_free(pblk);
	pblk_core_free(pblk);
	pblk_luns_free(pblk);
	pblk_area_free(pblk);

	kfree(pblk);
}

static void pblk_flush_writer(struct pblk *pblk)
{
	struct bio *bio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio) {
		pr_err("pblk: could not alloc tear down bio\n");
		return;
	}

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio->bi_rw = (REQ_WRITE | REQ_SYNC | REQ_FLUSH);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_sync_bio;

	ret = pblk_submit_io(pblk, bio, 0);
	if (ret == NVM_IO_OK)
		wait_for_completion_io(&wait);
	else if (ret != NVM_IO_DONE)
		pr_err("pblk: tear down bio failed\n");

	bio_put(bio);
}

static void pblk_pad_blk(struct pblk *pblk, struct pblk_block *rblk,
							int nr_free_secs)
{
	struct nvm_dev *dev = pblk->dev;
	struct bio *bio;
	struct nvm_rq *rqd;
	struct pblk_ctx *ctx;
	struct pblk_compl_ctx *c_ctx;
	void *pad_data;
	unsigned int bio_len;
	int nr_secs, err;

	pad_data = kzalloc(pblk->max_write_pgs * dev->sec_size, GFP_ATOMIC);
	if (!pad_data) {
		pr_err("pblk: could not allocate tear down pad data\n");
		return;
	}

	do {
		nr_secs = (nr_free_secs > pblk->max_write_pgs) ?
					pblk->max_write_pgs : nr_free_secs;

		rqd = mempool_alloc(pblk->w_rq_pool, GFP_ATOMIC);
		if (!rqd) {
			pr_err("pblk: could not alloc write req.\n ");
			goto free_pad_data;
		}
		memset(rqd, 0, pblk_w_rq_size);
		ctx = pblk_set_ctx(pblk, rqd);
		c_ctx = ctx->c_ctx;

		bio_len = nr_secs * dev->sec_size;
		bio = bio_map_kern(dev->q, pad_data, bio_len, GFP_ATOMIC);
		if (!bio) {
			pr_err("pblk: could not alloc tear down bio\n");
			goto free_rqd;
		}
		bio_get(bio);

		bio->bi_iter.bi_sector = 0; /* artificial bio */
		bio->bi_rw = WRITE;
		rqd->bio = bio;

		ctx->flags = PBLK_IOTYPE_PAD;
		c_ctx->sentry = 0;
		c_ctx->nr_valid = 0;
		c_ctx->nr_padded = nr_secs;

		if (pblk_setup_pad_rq(pblk, rblk, rqd, ctx)) {
			pr_err("pblk: could not setup tear down req.\n");
			goto free_bio;
		}

		err = nvm_submit_io(dev, rqd);
		if (err) {
			pr_err("pblk: I/O submission failed: %d\n", err);
			goto free_bio;
		}

		nr_free_secs -= nr_secs;
	} while (nr_free_secs > 0);

	kfree(pad_data);
	return;

free_bio:
	bio_put(bio);
free_rqd:
	mempool_free(rqd, pblk->w_rq_pool);
free_pad_data:
	kfree(pad_data);
}

/*
 * XXX: For now, we pad the whole block. In the future, pad only the pages that
 * are needed to guarantee that future reads will come, and delegate bringing up
 * the block for writing to the bring up recovery. Basically, this means
 * implementing l2p snapshot and in case of power failure, if a block belongs
 * to a target and it is not closed, scan the OOB area for each page to
 * recover the state of the block. There should only be NUM_LUNS active blocks
 * at any moment in time.
 */
static void pblk_pad_open_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	unsigned int i, mod;
	int nr_free_secs;

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock_lists);
		list_for_each_entry_safe(rblk, trblk, &rlun->open_list, list) {
			nr_free_secs = pblk_nr_free_secs(pblk, rblk);
			div_u64_rem(nr_free_secs, pblk->min_write_pgs, &mod);
			if (mod) {
				pr_err("pblk: corrupted block\n");
				continue;
			}

			pr_debug("pblk: padding %d sectors in blk:%lu\n",
						nr_free_secs, rblk->parent->id);

			/* empty block - no need for padding */
			if (nr_free_secs == pblk->nr_blk_dsecs) {
				__pblk_put_blk(pblk, rblk);
				continue;
			}

			pblk_pad_blk(pblk, rblk, nr_free_secs);
		}
		spin_unlock(&rlun->lock_lists);
	}

try:
	/* Wait until all padding I/Os complete */
	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock_lists);
		if (!list_empty(&rlun->open_list)) {
			spin_unlock(&rlun->lock_lists);
			schedule();
			goto try;
		}
		spin_unlock(&rlun->lock_lists);
	}
}

static void pblk_tear_down(struct pblk *pblk)
{
	pblk_flush_writer(pblk);
	pblk_pad_open_blks(pblk);
	pblk_rb_sync_l2p(&pblk->rwb);
	pblk_rwb_free(pblk);

	if (pblk_rb_tear_down_check(&pblk->rwb)) {
		pr_err("pblk: write buffer error on tear down\n");
		return;
	}

	/* TODO: Stop GC before freeing blocks */
	pblk_free_blks(pblk);

	pr_debug("pblk: consistent tear down\n");

	/* TODO:
	 *  - Save FTL snapshot for fast recovery
	 */
}

static void pblk_exit(void *private)
{
	struct pblk *pblk = private;

	down_write(&pblk_lock);
	del_timer(&pblk->gc_timer);
	flush_workqueue(pblk->krqd_wq);
	flush_workqueue(pblk->kgc_wq);
	pblk_tear_down(pblk);
	pblk_free(pblk);
	up_write(&pblk_lock);
}

static sector_t pblk_capacity(void *private)
{
	struct pblk *pblk = private;
	struct nvm_dev *dev = pblk->dev;
	sector_t reserved, provisioned;

	/* cur, gc, and two emergency blocks for each lun */
	reserved = pblk->nr_luns * dev->sec_per_blk * 4;
	provisioned = pblk->nr_secs - reserved;

	if (reserved > pblk->nr_secs) {
		pr_err("pblk: not enough space available to expose storage.\n");
		return 0;
	}

	sector_div(provisioned, 10);
	return provisioned * 9 * NR_PHY_IN_LOG;
}

static int pblk_blocks_init(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int lun, blk;
	int ret = 0;

	/* TODO: Try to recover from l2p snapshot. Only perform scanning in
	 * case of failure
	 */

	for (lun = 0; lun < pblk->nr_luns; lun++) {
		rlun = &pblk->luns[lun];
		for (blk = 0; blk < pblk->dev->blks_per_lun; blk++) {
			rblk = &rlun->blocks[blk];
			/* XXX: Pending on mm recovery */
			/* ret = pblk_scan_recover_blk(pblk, rblk); */
			/* if (ret) { */
				/* pr_err("nvm: pblk: could not recover l2p\n"); */
				/* goto out; */
			/* } */
		}
	}

out:
	return ret;
}

static int pblk_luns_configure(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];

		rblk = pblk_get_blk(pblk, rlun, 0);
		if (!rblk)
			goto err;

		pblk_set_lun_cur(rlun, rblk, 0);

		/* Emergency gc block */
		rblk = pblk_get_blk(pblk, rlun, 1);
		if (!rblk)
			goto err;
		rlun->gc_cur = rblk;
	}

	return 0;
err:
	pblk_put_blks(pblk);
	return -EINVAL;
}

static struct nvm_tgt_type tt_pblk;

static void *pblk_init(struct nvm_dev *dev, struct gendisk *tdisk,
						int lun_begin, int lun_end)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct pblk *pblk;
	sector_t soffset;
	int ret;

/*	if (dev->identity.dom & NVM_RSP_L2P) {
		pr_err("nvm: pblk: device has device-side translation table. Target not supported. (%x)\n",
							dev->identity.dom);
		return ERR_PTR(-EINVAL);
	}*/

	pblk = kzalloc(sizeof(struct pblk), GFP_KERNEL);
	if (!pblk)
		return ERR_PTR(-ENOMEM);

	pblk->instance.tt = &tt_pblk;
	pblk->dev = dev;
	pblk->disk = tdisk;

	bio_list_init(&pblk->requeue_bios);
	spin_lock_init(&pblk->bio_lock);
	spin_lock_init(&pblk->trans_lock);
	INIT_WORK(&pblk->ws_requeue, pblk_requeue);
	INIT_WORK(&pblk->ws_writer, pblk_submit_write);

	pblk->nr_luns = lun_end - lun_begin + 1;

	/* simple round-robin strategy */
	atomic_set(&pblk->next_lun, -1);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&pblk->inflight_writes, 0);
	atomic_set(&pblk->padded_writes, 0);
	atomic_set(&pblk->nr_flush, 0);
	atomic_set(&pblk->req_writes, 0);
	atomic_set(&pblk->sub_writes, 0);
	atomic_set(&pblk->sync_writes, 0);
	atomic_set(&pblk->compl_writes, 0);
	atomic_set(&pblk->inflight_reads, 0);
	atomic_set(&pblk->sync_reads, 0);
	atomic_set(&pblk->recov_writes, 0);
	atomic_set(&pblk->recov_gc_writes, 0);
	atomic_set(&pblk->requeued_writes, 0);
#endif

	ret = pblk_area_init(pblk, &soffset);
	if (ret < 0) {
		pr_err("pblk: could not initialize area\n");
		return ERR_PTR(ret);
	}
	pblk->soffset = soffset;

	ret = pblk_luns_init(pblk, lun_begin, lun_end);
	if (ret) {
		pr_err("pblk: could not initialize luns\n");
		goto err;
	}

	pblk->poffset = dev->sec_per_lun * lun_begin;
	pblk->lun_offset = lun_begin;

	ret = pblk_core_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize core\n");
		goto err;
	}

	ret = pblk_map_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize maps\n");
		goto err;
	}

	ret = pblk_blocks_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize state for blocks\n");
		goto err;
	}

	ret = pblk_luns_configure(pblk);
	if (ret) {
		pr_err("pblk: not enough blocks available in LUNs.\n");
		goto err;
	}

	ret = pblk_gc_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize gc\n");
		goto err;
	}

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	/* Signal the block layer that flush is supported */
	blk_queue_flush(tqueue, REQ_FLUSH | REQ_FUA);

	pr_info("pblk initialized with %u luns and %llu pages.\n",
			pblk->nr_luns, (unsigned long long)pblk->nr_secs);

	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(10));

	return pblk;
err:
	pblk_free(pblk);
	return ERR_PTR(ret);
}

#ifdef CONFIG_NVM_DEBUG
static void pblk_print_debug(void *private)
{
	struct pblk *pblk = private;
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	struct pblk_ctx *c;
	struct pblk_compl_ctx *c_ctx;
	unsigned int i;

	pr_info("pblk: %u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
				atomic_read(&pblk->inflight_writes),
				atomic_read(&pblk->inflight_reads),
				atomic_read(&pblk->req_writes),
				atomic_read(&pblk->nr_flush),
				atomic_read(&pblk->padded_writes),
				atomic_read(&pblk->sub_writes),
				atomic_read(&pblk->sync_writes),
				atomic_read(&pblk->compl_writes),
				atomic_read(&pblk->recov_writes),
				atomic_read(&pblk->recov_gc_writes),
				atomic_read(&pblk->requeued_writes),
				atomic_read(&pblk->sync_reads));

	pblk_rb_print_debug(&pblk->rwb);

	pblk_for_each_lun(pblk, rlun, i) {
		pr_info("LUN:%d\n", rlun->parent->id);

		spin_lock(&rlun->lock_lists);
		/* Print open blocks */
		list_for_each_entry(rblk, &rlun->open_list, list) {
			spin_lock(&rblk->lock);
			pr_info("pblk:open:\tblk:%lu\t%u\t%u\t%u\t%u\t%u\t%u\n",
					rblk->parent->id,
					pblk->dev->sec_per_blk,
					pblk->nr_blk_dsecs,
					bitmap_weight(rblk->pages,
							pblk->dev->sec_per_blk),
					bitmap_weight(rblk->sync_bitmap,
							pblk->dev->sec_per_blk),
					bitmap_weight(rblk->invalid_pages,
							pblk->dev->sec_per_blk),
					rblk->nr_invalid_pages);
			spin_unlock(&rblk->lock);
		}

		/* Print grown bad blocks not yet retired */
		list_for_each_entry(rblk, &rlun->bb_list, list) {
			spin_lock(&rblk->lock);
			pr_info("pblk:bad:\tblk:%lu\t%u\n",
				rblk->parent->id,
				bitmap_weight(rblk->pages,
						pblk->dev->sec_per_blk));
			spin_unlock(&rblk->lock);
		}
		spin_unlock(&rlun->lock_lists);
	}

	/* Print completion queue */
	list_for_each_entry(c, &pblk->compl_list, list) {
		c_ctx = c->c_ctx;
		pr_info("pblk:compl_list:\t%u\t%u\t%u\n",
			c_ctx->sentry,
			c_ctx->nr_valid,
			c_ctx->nr_padded);
	}
}
#else
static void pblk_print_debug(void *private)
{
}
#endif

/* physical block device target */
static struct nvm_tgt_type tt_pblk = {
	.name		= "pblk",
	.version	= {1, 0, 0},

	.make_rq	= pblk_make_rq,
	.capacity	= pblk_capacity,
	.end_io		= pblk_end_io,

	.init		= pblk_init,
	.exit		= pblk_exit,

	.print_debug	= pblk_print_debug,
};

static int __init pblk_module_init(void)
{
	return nvm_register_tgt_type(&tt_pblk);
}

static void pblk_module_exit(void)
{
	nvm_unregister_tgt_type(&tt_pblk);
}

module_init(pblk_module_init);
module_exit(pblk_module_exit);
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_AUTHOR("Javier Gonzalez <jg@lightnvm.io>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Physical Block-Device Target for Open-Channel SSDs");
