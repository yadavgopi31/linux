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
 * pblk-write.c - pblk's write path from write buffer to media
 */

#include "pblk.h"

/* rblk->lock must be taken */
static inline u64 pblk_next_base_sec(struct pblk *pblk, struct pblk_block *rblk,
				     int nr_secs)
{
	u64 old = rblk->cur_sec;

#ifdef CONFIG_NVM_DEBUG
	int i;
	int cur_sec = old;

	BUG_ON(rblk->cur_sec + nr_secs > pblk->nr_blk_dsecs);

	for (i = 0; i < nr_secs; i++) {
		WARN_ON(test_bit(cur_sec, rblk->sector_bitmap));
		cur_sec++;
	}
#endif

	bitmap_set(rblk->sector_bitmap, rblk->cur_sec, nr_secs);
	rblk->cur_sec += nr_secs;

	return old;
}

static u64 pblk_alloc_page(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 addr = ADDR_EMPTY;
	int nr_secs = pblk->min_write_pgs;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rblk->lock);
#endif

	if (block_is_full(pblk, rblk))
		goto out;

	addr = pblk_next_base_sec(pblk, rblk, nr_secs);

out:
	return addr;
}

/* The ppa in pblk_addr comes with an offset format, not a global format */
static void pblk_page_pad_invalidate(struct pblk *pblk, struct pblk_block *rblk,
				     struct ppa_addr a)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rblk->lock);
#endif

	WARN_ON(test_and_set_bit(a.ppa, rblk->invalid_bitmap));
	rblk->nr_invalid_secs++;

	pblk_rb_sync_init(&pblk->rwb, NULL);
	WARN_ON(test_and_set_bit(a.ppa, rblk->sync_bitmap));
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_blk_ws(pblk, rblk, pblk_close_blk);
	pblk_rb_sync_end(&pblk->rwb, NULL);
}

int pblk_map_page(struct pblk *pblk, struct pblk_block *rblk,
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
	paddr = pblk_alloc_page(pblk, rblk);

	if (paddr == ADDR_EMPTY) {
		spin_unlock(&rblk->lock);
		return 1;
	}

	for (i = 0; i < nr_secs; i++, paddr++) {
		if (paddr == ADDR_EMPTY) {
			/* We should always have available sectors for a full
			 * page write at this point. We get a new block for this
			 * LUN when the current block is full.
			 */
			pr_err("pblk: corrupted l2p mapping, blk:%lu,n:%d/%d\n",
					rblk->parent->id,
					i, nr_secs);
			spin_unlock(&rblk->lock);
			return -EINVAL;
		}

		/* ppa to be sent to the device */
		ppa_list[i] = pblk_blk_ppa_to_gaddr(dev, rblk->b_gen_ppa,
						global_addr(pblk, rblk, paddr));

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and only one of the writer threads have access to each
		 * specific entry at a time. Thus, it is safe to modify the
		 * context for the entry we are setting up for submission
		 * without taking any lock and/or memory barrier.
		 */
		if (i < valid_secs) {
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->paddr = paddr;
			w_ctx->ppa.ppa = ppa_list[i];
			w_ctx->ppa.rblk = rblk;
			meta_list[i].lba = w_ctx->lba;
			lba_list[paddr] = w_ctx->lba;
			rlpg->nr_lbas++;
		} else {
			meta_list[i].lba = ADDR_EMPTY;
			lba_list[paddr] = ADDR_EMPTY;
			pblk_page_pad_invalidate(pblk, rblk,
							addr_to_ppa(paddr));
			rlpg->nr_padded++;
		}
	}
	spin_unlock(&rblk->lock);

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(pblk->dev, ppa_list, nr_secs))
		WARN_ON(1);
#endif

	return 0;
}

int pblk_replace_blk(struct pblk *pblk, struct pblk_block *rblk,
		     struct pblk_lun *rlun, int lun_pos)
{
	rblk = pblk_blk_pool_get(pblk, rlun);
	if (!rblk)
		return 0;

	pblk_set_lun_cur(rlun, rblk);
	return pblk_map_replace_lun(pblk, lun_pos);
}

int pblk_write_setup_s(struct pblk *pblk, struct nvm_rq *rqd,
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

	return pblk_map_rr_page(pblk, c_ctx->sentry, &rqd->ppa_addr,
							&meta[0], 1, 1);

	return ret;
}

int pblk_write_setup_m(struct pblk *pblk, struct nvm_rq *rqd,
		       struct pblk_ctx *ctx, struct pblk_sec_meta *meta,
		       unsigned int valid_secs, int off)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	int min = pblk->min_write_pgs;

	return pblk_map_rr_page(pblk, c_ctx->sentry + off,
					&rqd->ppa_list[off],
					&meta[off], min, valid_secs);
}

int pblk_write_alloc_rq(struct pblk *pblk, struct nvm_rq *rqd,
			struct pblk_ctx *ctx, unsigned int nr_secs)
{
	/* Setup write request */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = nr_secs;
	rqd->flags |= pblk_set_progr_mode(pblk);

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

static int pblk_setup_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
			   struct pblk_ctx *ctx)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	unsigned int nr_secs = valid_secs + padded_secs;
	struct pblk_sec_meta *meta;
	unsigned int setup_secs;
	int min = pblk->min_write_pgs;
	int i;
	int ret = 0;

	ret = pblk_write_alloc_rq(pblk, rqd, ctx, nr_secs);
	if (ret)
		goto out;

	meta = rqd->meta_list;

	if (unlikely(nr_secs == 1)) {
		BUG_ON(padded_secs != 0);
		ret = pblk_write_setup_s(pblk, rqd, ctx, meta);
		goto out;
	}

	for (i = 0; i < nr_secs; i += min) {
		setup_secs = (i + min > valid_secs) ?
						(valid_secs % min) : min;
		ret = pblk_write_setup_m(pblk, rqd, ctx, meta, setup_secs, i);
		if (ret)
			goto out;
	}

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(pblk->dev, rqd->ppa_list, rqd->nr_ppas))
		WARN_ON(1);
#endif

out:
	return ret;
}

static int pblk_calc_secs_to_sync(struct pblk *pblk, unsigned long secs_avail,
				  unsigned long secs_to_flush)
{
	int max = pblk->max_write_pgs;
	int min = pblk->min_write_pgs;
	int secs_to_sync = 0;

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
		if (secs_to_flush)
			secs_to_sync = min;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!secs_to_sync && secs_to_flush);
#endif

	return secs_to_sync;
}

int pblk_submit_write(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct bio *bio;
	struct nvm_rq *rqd;
	struct pblk_ctx *ctx;
	struct pblk_compl_ctx *c_ctx;
	unsigned int pgs_read;
	unsigned int secs_avail, secs_to_sync, secs_to_com;
	unsigned int secs_to_flush = 0;
	unsigned long sync_point;
	unsigned long count;
	unsigned long pos;
	int err;

	/* Pre-check if we should start writing before doing allocations */
	secs_to_flush = pblk_rb_sync_point_count(&pblk->rwb);
	count = pblk_rb_count(&pblk->rwb);
	if (!secs_to_flush && count < pblk->max_write_pgs)
		return 1;

	rqd = pblk_alloc_rqd(pblk, WRITE);
	if (IS_ERR(rqd)) {
		pr_err("pblk: not able to create write req.\n");
		return 1;
	}
	ctx = pblk_set_ctx(pblk, rqd);
	c_ctx = ctx->c_ctx;

	bio = bio_alloc(GFP_KERNEL, pblk->max_write_pgs);
	if (!bio) {
		pr_err("pblk: not able to create write bio\n");
		goto fail_rqd;
	}

	/* Count available entries on rb, and lock reader */
	secs_avail = pblk_rb_read_lock(&pblk->rwb);
	if (!secs_avail)
		goto fail_bio;

	secs_to_flush = pblk_rb_sync_point_count(&pblk->rwb);
	secs_to_sync = pblk_calc_secs_to_sync(pblk, secs_avail, secs_to_flush);
	if (secs_to_sync < 0) {
		pr_err("pblk: bad buffer sync calculation\n");
		pblk_rb_read_unlock(&pblk->rwb);
		goto fail_bio;
	}

	secs_to_com = (secs_to_sync > secs_avail) ? secs_avail : secs_to_sync;
	pos = pblk_rb_read_commit(&pblk->rwb, secs_to_com);

	if (!secs_to_com)
		goto fail_bio;

	pgs_read = pblk_rb_read_to_bio(&pblk->rwb, bio, ctx, pos, secs_to_sync,
						secs_avail, &sync_point);
	if (!pgs_read)
		goto fail_sync;

	if (secs_to_flush <= secs_to_sync)
		pblk_rb_sync_point_reset(&pblk->rwb, sync_point);

	if (c_ctx->nr_padded)
		if (pblk_bio_add_pages(pblk, bio, GFP_KERNEL, c_ctx->nr_padded))
			goto fail_sync;

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio->bi_rw = WRITE;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
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
	return 0;
fail_free_bio:
	if (c_ctx->nr_padded)
		pblk_bio_free_pages(pblk, bio, secs_to_sync, c_ctx->nr_padded);
fail_sync:
	/* Kick the queue to avoid a deadlock in the case that no new I/Os are
	 * coming in.
	 */
	/*pblk_write_kick(pblk);*/
fail_bio:
	bio_put(bio);
fail_rqd:
	pblk_free_rqd(pblk, rqd, WRITE);

	return 1;
}

int pblk_write_ts(void *data)
{
	struct pblk *pblk = data;

	/* while (!kthread_should_stop()) { */
	while(1) {
		if (!pblk_submit_write(pblk))
			continue;
		/* set_current_state(TASK_INTERRUPTIBLE); */
		io_schedule();
	}

	return 0;
}

static void pblk_sync_buffer(struct pblk *pblk, struct pblk_block *rblk,
			     u64 block_ppa, int flags)
{
	WARN_ON(test_and_set_bit(block_ppa, rblk->sync_bitmap));

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->sync_writes);
#endif

	/* If last page completed, then this is not a grown bad block */
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_blk_ws(pblk, rblk, pblk_close_blk);
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
		pblk_sync_buffer(pblk, w_ctx->ppa.rblk, w_ctx->paddr,
								w_ctx->flags);
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
	pblk_free_rqd(pblk, rqd, WRITE);

	return ret;
}

static unsigned long pblk_end_queued_w_bio(struct pblk *pblk,
					   struct nvm_rq *rqd,
					   struct pblk_ctx *ctx)
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

	atomic_sub(c_ctx->nr_valid, &pblk->write_inflight);

#ifdef CONFIG_NVM_DEBUG
	atomic_sub(c_ctx->nr_valid, &pblk->inflight_writes);
#endif

	/* Kick write thread if waiting */
	if (waitqueue_active(&pblk->wait))
		wake_up_all(&pblk->wait);

	pos = pblk_rb_sync_init(&pblk->rwb, &flags);

	if (c_ctx->sentry == pos) {
		pos = pblk_end_w_bio(pblk, rqd, ctx);

retry:
		list_for_each_entry_safe(c, r, &pblk->compl_list, list) {
			rqd = nvm_rq_from_pdu(c);
			c_ctx = c->c_ctx;
			if (c_ctx->sentry == pos) {
				pos = pblk_end_queued_w_bio(pblk, rqd, c);
				goto retry;
			}
		}
	} else {
		list_add_tail(&ctx->list, &pblk->compl_list);
	}

	pblk_rb_sync_end(&pblk->rwb, &flags);
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
 *  This function assumes that ppas in rqd are in generic mode. This is,
 *  nvm_addr_to_generic_mode(dev, rqd) has been called.
 *
 *  TODO: Depending on the type of memory, try write retry
 */
static void pblk_end_w_fail(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct nvm_dev *dev = pblk->dev;
	void *comp_bits = &rqd->ppa_status;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	struct pblk_rec_ctx *recovery;
	struct ppa_addr ppa, prev_ppa;
	unsigned int c_entries;
	int nr_ppas = rqd->nr_ppas;
	int bit;
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
	 */
	if (nr_ppas == 1)
		return;

	recovery = mempool_alloc(pblk->rec_pool, GFP_ATOMIC);
	if (!recovery) {
		pr_err("pblk: could not allocate recovery context\n");
		return;
	}
	INIT_LIST_HEAD(&recovery->failed);

	c_entries = find_first_bit(comp_bits, nr_ppas);

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

		/* Mark block as bad in the media manager */
		nvm_mark_blk(dev, ppa, NVM_BLK_ST_BAD);

		prev_ppa.ppa = ppa.ppa;
		pblk_run_recovery(pblk, w_ctx->ppa.rblk);
	}

out:
	ret = pblk_recov_setup_rq(pblk, ctx, recovery, comp_bits, c_entries);
	if (ret)
		pr_err("pblk: could not recover from write failure\n");

	INIT_WORK(&recovery->ws_rec, pblk_submit_rec);
	queue_work(pblk->kw_wq, &recovery->ws_rec);

	pblk_compl_queue(pblk, rqd, ctx);
}

void pblk_end_io_write(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_ctx *ctx;

	if (rqd->error == NVM_RSP_ERR_FAILWRITE) {
		nvm_addr_to_generic_mode(dev, rqd);
		return pblk_end_w_fail(pblk, rqd);
	}

	ctx = pblk_set_ctx(pblk, rqd);

	if (ctx->flags & PBLK_IOTYPE_SYNC)
		return;

	if (ctx->flags & PBLK_IOTYPE_CLOSE_BLK)
		return pblk_end_close_blk_bio(pblk, rqd, 1);

	pblk_compl_queue(pblk, rqd, ctx);
	/*pblk_write_kick(pblk);*/
}

