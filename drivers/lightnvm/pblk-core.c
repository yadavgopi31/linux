/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <jg@lightnvm.io>
 *                  Matias Bjorling <m@bjorling.me>
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
 * pblk-core.c - pblk's core functionality
 *
 * TODO:
 *   - Implement L2P snapshot on graceful tear down.
 *   - Separate mapping from actual stripping strategy to enable
 *     workload-specific optimizations
 *   - Implement support for new MLC & TLC chips
 */

#include "pblk.h"
#include <linux/time.h>

struct nvm_rq *pblk_alloc_rqd(struct pblk *pblk, int rw)
{
	mempool_t *pool;
	struct nvm_rq *rqd;
	int rq_size;

	if (rw == WRITE) {
		pool = pblk->w_rq_pool;
		rq_size = pblk_w_rq_size;
	} else {
		pool = pblk->r_rq_pool;
		rq_size = pblk_r_rq_size;
	}

	rqd = mempool_alloc(pool, GFP_KERNEL);
	if (!rqd)
		return ERR_PTR(-ENOMEM);

	memset(rqd, 0, rq_size);
	return rqd;
}

void pblk_free_rqd(struct pblk *pblk, struct nvm_rq *rqd, int rw)
{
	mempool_t *pool;
	
	if (rw == WRITE)
		pool = pblk->w_rq_pool;
	else
		pool = pblk->r_rq_pool;

	mempool_free(rqd, pool);
}

void pblk_print_failed_rqd(struct pblk *pblk, struct nvm_rq *rqd, int error)
{
	int offset = -1;
	struct ppa_addr p;

	if (rqd->nr_ppas ==  1) {
		p = dev_to_generic_addr(pblk->dev, rqd->ppa_addr);
		print_ppa(&p, "rqd", error);
		return;
	}

	while ((offset =
		find_next_bit((void *)&rqd->ppa_status, rqd->nr_ppas,
						offset + 1)) < rqd->nr_ppas) {
		p = dev_to_generic_addr(pblk->dev, rqd->ppa_list[offset]);
		print_ppa(&p, "rqd", error);
	}
}

/*
 * Increment 'v', if 'v' is below 'below'. Returns true if we succeeded,
 * false if 'v' + 1 would be bigger than 'below'.
 */
static bool atomic_inc_below(atomic_t *v, int below, int inc)
{
	int cur = atomic_read(v);

	for (;;) {
		int old;

		if (cur >= below)
			return false;
		old = atomic_cmpxchg(v, cur, cur + inc);
		if (old == cur)
			break;
		cur = old;
	}

	return true;
}

static inline bool __pblk_may_submit_write(struct pblk *pblk, int nr_secs)
{
	return atomic_inc_below(&pblk->write_inflight, pblk->write_cur_speed, nr_secs);
}

void pblk_may_submit_write(struct pblk *pblk, int nr_secs)
{
	DEFINE_WAIT(wait);

	if (__pblk_may_submit_write(pblk, nr_secs))
		return;

	do {
		prepare_to_wait_exclusive(&pblk->wait, &wait,
						TASK_UNINTERRUPTIBLE);

		if (__pblk_may_submit_write(pblk, nr_secs))
			break;

		io_schedule();
	} while (1);

	finish_wait(&pblk->wait, &wait);
}

void pblk_bio_free_pages(struct pblk *pblk, struct bio *bio, int off,
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

int pblk_bio_add_pages(struct pblk *pblk, struct bio *bio, gfp_t flags,
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

void pblk_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	complete(waiting);
}

static int pblk_setup_write_to_cache(struct pblk *pblk, struct bio *bio,
				     struct bio *ctx_bio, unsigned long *pos,
				     unsigned int nr_upd, unsigned int nr_com)
{
	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
	if (!pblk_rb_may_write(&pblk->rwb, nr_upd, nr_com, pos))
		return 0;

	ctx_bio = (bio->bi_opf & REQ_PREFLUSH) ? bio : NULL;
	return 1;
}

/*
 * Copy data from current bio to write buffer. This if necessary to guarantee
 * that (i) writes to the media at issued at the right granurality and (ii) that
 * memory-specific constrains are respected (e.g., TLC memories need to write
 * upper, medium and lower pages to guarantee that data has been persisted).
 *
 * This path is exclusively taken by user I/O.
 *
 * return: 1 if bio has been written to buffer, 0 otherwise.
 */
static int __pblk_write_to_cache(struct pblk *pblk, struct bio *bio,
				 unsigned long flags, unsigned int nr_entries)
{
	sector_t laddr = pblk_get_laddr(bio);
	struct bio *ctx_bio = (bio->bi_opf & REQ_PREFLUSH) ? bio : NULL;
	struct pblk_w_ctx w_ctx;
	unsigned long bpos;
	unsigned int i;
	int ret = (ctx_bio) ? NVM_IO_OK : NVM_IO_DONE;

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
	if (!pblk_rb_may_write(&pblk->rwb, nr_entries, nr_entries, &bpos))
		return NVM_IO_REQUEUE;

	w_ctx.bio = ctx_bio;
	w_ctx.flags = flags;
	w_ctx.priv = NULL;
	w_ctx.paddr = 0;
	ppa_set_empty(&w_ctx.ppa.ppa);

	for (i = 0; i < nr_entries; i++) {
		void *data = bio_data(bio);
		struct ppa_addr ppa;
		unsigned long pos = bpos + i;

		w_ctx.lba = laddr + i;

		pblk_rb_write_entry(&pblk->rwb, data, w_ctx, pos);
		ppa = pblk_cacheline_to_ppa(pblk_rb_wrap_pos(&pblk->rwb, pos));

		pblk_update_map(pblk, w_ctx.lba, NULL, ppa);

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

	return ret;
}

int pblk_write_list_to_cache(struct pblk *pblk, struct bio *bio,
			     u64 *lba_list,
			     struct pblk_kref_buf *ref_buf,
			     unsigned int nr_secs,
			     unsigned int nr_rec_secs,
			     unsigned long flags,
			     struct pblk_block *gc_rblk)
{
	struct pblk_w_ctx w_ctx;
	struct bio *ctx_bio = NULL;
	unsigned long bpos;
	unsigned int i, valid_secs = 0;

	BUG_ON(!bio_has_data(bio) || (nr_rec_secs != bio->bi_vcnt));

	if (!pblk_setup_write_to_cache(pblk, bio, ctx_bio, &bpos,
							nr_secs, nr_rec_secs))
		return -1;

	w_ctx.bio = ctx_bio;
	w_ctx.flags = flags;
	w_ctx.priv = ref_buf;
	w_ctx.paddr = 0;
	ppa_set_empty(&w_ctx.ppa.ppa);

	for (i = 0, valid_secs = 0; i < nr_secs; i++) {
		void *data = bio_data(bio);
		struct ppa_addr ppa;
		unsigned int pos = bpos + valid_secs;

		if (lba_list[i] == ADDR_EMPTY)
			continue;

		w_ctx.lba = lba_list[i];

#ifdef CONFIG_NVM_DEBUG
		BUG_ON(!(flags & PBLK_IOTYPE_REF));
#endif
		kref_get(&ref_buf->ref);

		pblk_rb_write_entry(&pblk->rwb, data, w_ctx, pos);
		ppa = pblk_cacheline_to_ppa(pblk_rb_wrap_pos(&pblk->rwb, pos));

		pblk_update_map_gc(pblk, w_ctx.lba, NULL, ppa, gc_rblk);

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
		valid_secs++;
	}

	pblk_may_submit_write(pblk, nr_rec_secs);

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_rec_secs != valid_secs);
	atomic_add(valid_secs, &pblk->inflight_writes);
	atomic_add(valid_secs, &pblk->recov_gc_writes);
#endif

	return NVM_IO_OK;
}

int pblk_calc_max_wr_speed(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	int wr_per_sec = 1000000000 / dev->identity.groups[0].tprt;
	int sect_per_sec = (wr_per_sec * dev->sec_per_pl * dev->nr_planes) >> 2;

	/*TODO: divided by constant factor*/
	return sect_per_sec * pblk->nr_luns / 4;
}

static void pblk_write_user_update(struct pblk *pblk)
{
	int i;
	unsigned int avail = 0;
	struct nvm_lun *lun;
	int high, low;

	for (i = 0; i < pblk->nr_luns; i++) {
		lun = pblk->luns[i].parent;
		//spin_lock(&lun->lock);
		avail += lun->nr_free_blocks;
		//spin_unlock(&lun->lock);
	}

	high = pblk->total_blocks / PBLK_USER_HIGH_THRS;
	low = pblk->total_blocks / PBLK_USER_LOW_THRS;

	if (avail > high)
		pblk->write_cur_speed = pblk->write_max_speed;
	else if (avail > low && avail < high)
	{
		/* redo to power of two calculations */
		int perc = ((avail * 100)) / (high - low);
		pblk->write_cur_speed = (pblk->write_max_speed / 100) * perc;
	} else {
		pblk->write_cur_speed = 0;
	}
}

void pblk_write_timer_fn(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	/* Kick write queue if waiting */
	if (waitqueue_active(&pblk->wait))
		wake_up_nr(&pblk->wait, 1);

	/* kick the write thread every tick to flush outstanding data */
	pblk_write_kick(pblk);

	/* write user speed calc */
	pblk_write_user_update(pblk);

	mod_timer(&pblk->wtimer, jiffies + msecs_to_jiffies(1000));
}

int pblk_write_to_cache(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	int nr_secs = pblk_get_secs(bio);
	int ret = NVM_IO_DONE;

	if (bio->bi_opf & REQ_PREFLUSH) {
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

retry:
	if (unlikely(pblk_gc_is_emergency(pblk)))
		return NVM_IO_REQUEUE;

	ret = __pblk_write_to_cache(pblk, bio, flags, nr_secs);
	if (ret == NVM_IO_REQUEUE) {
		schedule();
		goto retry;
	}

	pblk_may_submit_write(pblk, nr_secs);

	spin_lock_irq(&pblk->lock);
	pblk->write_cnt += nr_secs;
	if (pblk->write_cnt > PBLK_KICK_SECTS) {
		pblk->write_cnt -= PBLK_KICK_SECTS;
		spin_unlock_irq(&pblk->lock);

		pblk_write_kick(pblk);
	} else
		spin_unlock_irq(&pblk->lock);


#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_secs, &pblk->inflight_writes);
	atomic_add(nr_secs, &pblk->req_writes);
#endif

	/* Use count as a heuristic for setting up a job in workqueue */
	if (bio->bi_opf & REQ_PREFLUSH)
		pblk_write_kick(pblk);

out:
	return ret;
}

void pblk_flush_writer(struct pblk *pblk)
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
	bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;
	bio_set_op_attrs(bio, REQ_OP_WRITE, WRITE_FLUSH);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_sync_bio;

	ret = pblk_write_to_cache(pblk, bio, 0);
	if (ret == NVM_IO_OK)
		wait_for_completion_io(&wait);
	else if (ret != NVM_IO_DONE)
		pr_err("pblk: tear down bio failed\n");

	if (bio->bi_error)
		pr_err("pblk: flush sync write failed (%u)\n", bio->bi_error);

	bio_put(bio);
}

static void pblk_page_invalidate(struct pblk *pblk, struct pblk_addr *a)
{
	struct pblk_block *rblk = a->rblk;
	u64 block_ppa;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nvm_addr_in_cache(a->ppa));
	BUG_ON(ppa_empty(a->ppa));
#endif

	block_ppa = pblk_gaddr_to_pg_offset(pblk->dev, a->ppa);

	spin_lock(&rblk->lock);
	WARN_ON(test_and_set_bit(block_ppa, rblk->invalid_bitmap));
	rblk->nr_invalid_secs++;
	spin_unlock(&rblk->lock);
}

static void pblk_invalidate_range(struct pblk *pblk, sector_t slba,
				  unsigned int nr_secs)
{
	sector_t i;

	spin_lock(&pblk->trans_lock);
	for (i = slba; i < slba + nr_secs; i++) {
		struct pblk_addr *gp = &pblk->trans_map[i];

		if (gp->rblk)
			pblk_page_invalidate(pblk, gp);
		ppa_set_empty(&gp->ppa);
		gp->rblk = NULL;
	}
	spin_unlock(&pblk->trans_lock);
}

void pblk_discard(struct pblk *pblk, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t nr_secs = bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;

	pblk_invalidate_range(pblk, slba, nr_secs);
}

struct ppa_addr pblk_get_lba_map(struct pblk *pblk, sector_t lba)
{
	struct pblk_addr *gp;
	struct ppa_addr ppa;

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[lba];
	ppa = gp->ppa;
	spin_unlock(&pblk->trans_lock);

	return ppa;
}

/* Put block back to media manager but do not free rblk structures */
void pblk_retire_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	nvm_put_blk(pblk->dev, rblk->parent);
}

static void pblk_init_rlpg(struct pblk *pblk, struct pblk_block *rblk,
			   struct pblk_blk_rec_lpg *rlpg)
{
	u64 *lbas = pblk_rlpg_to_llba(rlpg);
	unsigned long *bitmaps;
	int nr_entries = pblk->nr_blk_dsecs;

	rblk->cur_sec = 0;
	rblk->nr_invalid_secs = 0;
	rblk->rlpg = rlpg;

	bitmaps = (void *)(lbas + nr_entries);

	rblk->sector_bitmap = bitmaps;
	rblk->sync_bitmap = (rblk->sector_bitmap) + rlpg->bitmap_len;
	rblk->invalid_bitmap = (rblk->sync_bitmap) + rlpg->bitmap_len;
}

struct pblk_blk_rec_lpg *pblk_alloc_blk_meta(struct pblk *pblk,
					     struct pblk_block *rblk,
					     u32 status)
{
	struct pblk_blk_rec_lpg *rlpg = NULL;
	unsigned int rlpg_len, req_len, bitmap_len;

	if (pblk_recov_calc_meta_len(pblk, &bitmap_len, &rlpg_len, &req_len))
		goto out;

	rlpg = mempool_alloc(pblk->blk_meta_pool, GFP_KERNEL);
	if (!rlpg)
		goto out;
	memset(rlpg, 0, req_len);

	rlpg->status = status;
	rlpg->rlpg_len = rlpg_len;
	rlpg->req_len = req_len;
	rlpg->bitmap_len = bitmap_len;
	rlpg->crc = 0;
	rlpg->nr_lbas = 0;
	rlpg->nr_padded = 0;

	pblk_init_rlpg(pblk, rblk, rlpg);

out:
	return rlpg;
}

struct pblk_block *pblk_get_blk(struct pblk *pblk, struct pblk_lun *rlun)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun = rlun->parent;
	struct nvm_block *blk;
	struct pblk_block *rblk;
	struct pblk_blk_rec_lpg *rlpg;
	int flags;

retry:
	blk = nvm_get_blk(pblk->dev, lun);
	if (!blk)
		return NULL;

	rblk = pblk_get_rblk(rlun, blk->id);
	blk->priv = rblk;

	rlpg = pblk_alloc_blk_meta(pblk, rblk, PBLK_BLK_ST_OPEN);
	if (!rlpg)
		goto fail_put_blk;

	/* TODO: For now, we erase blocks as we get them. The media manager will
	 * do this when as part of the GC scheduler
	 */
	flags = pblk_set_progr_mode(pblk);

	if (nvm_erase_blk(dev, rblk->parent, flags)) {
		struct ppa_addr ppa, gen_ppa;;

		/* Mark block as bad and return it to media manager */
		ppa = pblk_ppa_to_gaddr(dev, block_to_addr(pblk, rblk));
		gen_ppa = generic_to_dev_addr(dev, ppa);

		nvm_mark_blk(dev, ppa, NVM_BLK_ST_BAD);
		nvm_set_bb_tbl(dev, &gen_ppa, 1, NVM_BLK_T_GRWN_BAD);
		pblk_retire_blk(pblk, rblk);

		inc_stat(pblk, &pblk->erase_failed, 0);
		print_ppa(&ppa, "erase", 0);
		goto retry;
	}

	return rblk;

fail_put_blk:
	pblk_put_blk(pblk, rblk);
	return NULL;
}

void pblk_set_lun_cur(struct pblk_lun *rlun, struct pblk_block *rblk)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rlun->lock);

	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(rlun->pblk, rlun->cur) &&
							!block_is_bad(rblk));
		spin_unlock(&rlun->cur->lock);
	}
#endif

	rlun->cur = rblk;
}

void pblk_run_blk_ws(struct pblk *pblk, struct pblk_block *rblk,
		     void (*work)(struct work_struct *))
{
	struct pblk_block_ws *blk_ws;

	blk_ws = mempool_alloc(pblk->blk_ws_pool, GFP_ATOMIC);
	if (!blk_ws) {
		pr_err("pblk: unable to queue block work.");
		return;
	}

	blk_ws->pblk = pblk;
	blk_ws->rblk = rblk;

	INIT_WORK(&blk_ws->ws_blk, work);
	queue_work(pblk->kgc_wq, &blk_ws->ws_blk);
}

void pblk_end_close_blk_bio(struct pblk *pblk, struct nvm_rq *rqd, int run_gc)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_close_ctx *c_ctx = ctx->c_ctx;

	up(&c_ctx->rblk->rlun->wr_sem);

	if (run_gc)
		pblk_run_blk_ws(pblk, c_ctx->rblk, pblk_gc_queue);

	nvm_free_rqd_ppalist(dev, rqd);
	bio_put(rqd->bio);
	kfree(rqd);
}

static void pblk_end_w_pad(struct pblk *pblk, struct nvm_rq *rqd,
			   struct pblk_ctx *ctx)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;

	BUG_ON(c_ctx->nr_valid != 0);

	if (c_ctx->nr_padded > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);

	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, WRITE);
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

int pblk_update_map(struct pblk *pblk, sector_t laddr, struct pblk_block *rblk,
		    struct ppa_addr ppa)
{
	struct pblk_addr *gp;
	int ret = 0;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!rblk &&
		pblk_rb_pos_oob(&pblk->rwb, nvm_addr_to_cacheline(ppa)));
#endif

	BUG_ON(laddr >= pblk->nr_secs);

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];

	if (gp->rblk)
		pblk_page_invalidate(pblk, gp);

	gp->ppa = ppa;
	gp->rblk = rblk;

	spin_unlock(&pblk->trans_lock);
	return ret;
}

int pblk_update_map_gc(struct pblk *pblk, sector_t laddr,
		       struct pblk_block *rblk, struct ppa_addr ppa,
		       struct pblk_block *gc_rblk)
{
	struct pblk_addr *gp;
	int ret = 0;

	BUG_ON(laddr >= pblk->nr_secs);

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];

	/* Prevent updated entries to be overwritten by GC */
	if (gp->rblk && gc_rblk->parent->id != gp->rblk->parent->id)
		goto out;

	gp->ppa = ppa;
	gp->rblk = rblk;

out:
	spin_unlock(&pblk->trans_lock);
	return ret;
}

static int pblk_setup_pad_rq(struct pblk *pblk, struct pblk_block *rblk,
			     struct nvm_rq *rqd, struct pblk_ctx *ctx)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	unsigned int nr_secs = valid_secs + padded_secs;
	struct pblk_sec_meta *meta;
	int min = pblk->min_write_pgs;
	int i;
	int ret = 0;

	ret = pblk_write_alloc_rq(pblk, rqd, ctx, nr_secs);
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

		ret = pblk_map_page(pblk, rblk, c_ctx->sentry, &rqd->ppa_addr,
								&meta[0], 1, 0);

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
		ret = pblk_map_page(pblk, rblk, c_ctx->sentry + i,
						&rqd->ppa_list[i],
						&meta[i], min, 0);

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
		WARN_ON(1);
#endif

out:
	return ret;
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
	DECLARE_COMPLETION_ONSTACK(wait);

	pad_data = kzalloc(pblk->max_write_pgs * dev->sec_size, GFP_KERNEL);
	if (!pad_data)
		return;

	do {
		nr_secs = (nr_free_secs > pblk->max_write_pgs) ?
					pblk->max_write_pgs : nr_free_secs;

		rqd = pblk_alloc_rqd(pblk, WRITE);
		if (IS_ERR(rqd)) {
			pr_err("pblk: could not alloc write req.\n ");
			goto free_pad_data;
		}
		ctx = pblk_set_ctx(pblk, rqd);
		c_ctx = ctx->c_ctx;

		bio_len = nr_secs * dev->sec_size;
		bio = bio_map_kern(dev->q, pad_data, bio_len, GFP_KERNEL);
		if (!bio) {
			pr_err("pblk: could not alloc tear down bio\n");
			goto free_rqd;
		}

		bio->bi_iter.bi_sector = 0; /* artificial bio */
		bio->bi_opf = WRITE;
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		bio->bi_private = &wait;
		bio->bi_end_io = pblk_end_sync_bio;
		rqd->bio = bio;

		ctx->flags = PBLK_IOTYPE_SYNC;
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
		wait_for_completion_io(&wait);
		pblk_end_w_pad(pblk, rqd, ctx);

		nr_free_secs -= nr_secs;
	} while (nr_free_secs > 0);

	kfree(pad_data);
	return;

free_bio:
	bio_put(bio);
free_rqd:
	pblk_free_rqd(pblk, rqd, WRITE);
free_pad_data:
	kfree(pad_data);
}

static inline u64 pblk_nr_free_secs(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 free_secs = pblk->nr_blk_dsecs;

	spin_lock(&rblk->lock);
	free_secs -= bitmap_weight(rblk->sector_bitmap, pblk->nr_blk_dsecs);
	spin_unlock(&rblk->lock);

	return free_secs;
}

static void pblk_free_blk_meta(struct pblk *pblk, struct pblk_block *rblk)
{
	/* All bitmaps are allocated together with the rlpg structure */
	mempool_free(rblk->rlpg, pblk->blk_meta_pool);
}

/*
 * TODO: For now, we pad the whole block. In the future, pad only the pages that
 * are needed to guarantee that future reads will come, and delegate bringing up
 * the block for writing to the bring up recovery. Basically, this means
 * implementing l2p snapshot and in case of power failure, if a block belongs
 * to a target and it is not closed, scan the OOB area for each page to
 * recover the state of the block. There should only be NUM_LUNS active blocks
 * at any moment in time.
 */
void pblk_pad_open_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	unsigned int i, mod;
	int nr_free_secs;
	LIST_HEAD(open_list);

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock_lists);
		list_cut_position(&open_list, &rlun->open_list,
							rlun->open_list.prev);
		spin_unlock(&rlun->lock_lists);

		list_for_each_entry_safe(rblk, trblk, &open_list, list) {
			nr_free_secs = pblk_nr_free_secs(pblk, rblk);
			div_u64_rem(nr_free_secs, pblk->min_write_pgs, &mod);
			if (mod) {
				pr_err("pblk: corrupted block\n");
				continue;
			}

			/* empty block - no need for padding */
			if (nr_free_secs == pblk->nr_blk_dsecs) {
				pblk_put_blk_unlocked(pblk, rblk);
				continue;
			}

			pr_debug("pblk: padding %d sectors in blk:%lu\n",
						nr_free_secs, rblk->parent->id);

			pblk_pad_blk(pblk, rblk, nr_free_secs);
		}

		spin_lock(&rlun->lock_lists);
		list_splice(&open_list, &rlun->open_list);
		spin_unlock(&rlun->lock_lists);
	}

	/* Wait until padding completes and blocks are closed */
	pblk_for_each_lun(pblk, rlun, i) {
retry:
		spin_lock(&rlun->lock_lists);
		if (!list_empty(&rlun->open_list)) {
			spin_unlock(&rlun->lock_lists);
			io_schedule();
			goto retry;
		}
		spin_unlock(&rlun->lock_lists);
	}
}

void pblk_free_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	unsigned int i;

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock);
		list_for_each_entry_safe(rblk, trblk, &rlun->prio_list, prio) {
			pblk_free_blk_meta(pblk, rblk);
			list_del(&rblk->prio);
		}
		spin_unlock(&rlun->lock);
	}
}

void pblk_put_blk_unlocked(struct pblk *pblk, struct pblk_block *rblk)
{
	nvm_put_blk(pblk->dev, rblk->parent);
	list_del(&rblk->list);
	pblk_free_blk_meta(pblk, rblk);
}

void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock_lists);
	pblk_put_blk_unlocked(pblk, rblk);
	spin_unlock(&rlun->lock_lists);
}

