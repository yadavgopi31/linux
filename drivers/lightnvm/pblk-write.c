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
 */

#include "pblk.h"

static struct pblk_lun *get_next_lun(struct pblk *pblk)
{
	int next = atomic_inc_return(&pblk->next_lun);

	return &pblk->luns[next % pblk->nr_luns];
}

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
	rblk->nr_invalid_secs++;
	WARN_ON(test_and_set_bit(a.ppa, rblk->invalid_bitmap));

	WARN_ON(test_and_set_bit(a.ppa, rblk->sync_bitmap));
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_blk_ws(pblk, rblk, pblk_close_blk);
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

static int pblk_replace_blk(struct pblk *pblk, struct pblk_block *rblk,
			    struct pblk_lun *rlun, int is_bb)
{
	rblk = pblk_blk_pool_get(pblk, rlun);
	if (!rblk)
		return 0;

	pblk_set_lun_cur(rlun, rblk);
	return 1;
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
	struct pblk_block *rblk;
	struct pblk_lun *rlun;
	int gen_emergency_gc;
	int ret = 0;

	gen_emergency_gc = pblk_gc_is_emergency(pblk);
	rlun = pblk_get_lun_rr(pblk, gen_emergency_gc);

try_lun:
	spin_lock(&rlun->lock);

try_cur:
	rblk = rlun->cur;

	if (block_is_full(pblk, rblk)) {
		if (!pblk_replace_blk(pblk, rblk, rlun, 0)) {
			spin_unlock(&rlun->lock);
			schedule();
			goto try_lun;
		}
		goto try_cur;
	}

	/* Account for grown bad blocks */
	if (unlikely(block_is_bad(rblk))) {
		if (!pblk_replace_blk(pblk, rblk, rlun, 1)) {
			spin_unlock(&rlun->lock);
			schedule();
			goto try_lun;
		}
		goto try_cur;
	}

	ret = pblk_map_page(pblk, rblk, sentry, ppa_list, meta_list,
							nr_secs, valid_secs);

	spin_unlock(&rlun->lock);
	return ret;
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

	return pblk_map_rr_page(pblk, c_ctx->sentry, &rqd->ppa_addr,
							&meta[0], 1, 1);

	return ret;
}

int pblk_setup_w_multi(struct pblk *pblk, struct nvm_rq *rqd,
		       struct pblk_ctx *ctx, struct pblk_sec_meta *meta,
		       unsigned int valid_secs, int off)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	int min = pblk->min_write_pgs;

	return pblk_map_rr_page(pblk, c_ctx->sentry + off,
					&rqd->ppa_list[off],
					&meta[off], min, valid_secs);
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
		return 0;

	rqd = pblk_alloc_rqd(pblk, WRITE);
	if (IS_ERR(rqd)) {
		pr_err("pblk: not able to create write req.\n");
		return 0;
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
	return 1;
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

	return 0;
}


