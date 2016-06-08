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
#include "pblk-gc.h"
#include "pblk-recovery.h"

int pblk_init_blk(struct pblk *pblk, struct pblk_block *rblk, u32 status)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_blk_rec_lpg *rlpg;
	unsigned int rlpg_len, req_len, bitmap_len;
	int nr_entries = pblk->nr_blk_dsecs;
	int nr_bitmaps = 3; /* sectors, sync, invalid */

	bitmap_len = BITS_TO_LONGS(nr_entries);
	rlpg_len = sizeof(struct pblk_blk_rec_lpg) +
			(nr_entries * sizeof(u64)) +
			(nr_bitmaps * bitmap_len * sizeof(unsigned long));
	req_len = dev->sec_per_pl * dev->sec_size;

	if (rlpg_len > req_len) {
		pr_err("pblk: metadata is too large for last page size\n");
		return -EINVAL;
	}

	rlpg = kzalloc(req_len, GFP_KERNEL);
	if (!rlpg) {
		pr_err("pblk: cannot allocate recovery ppa list\n");
		return -ENOMEM;
	}
	rlpg->status = status;
	rlpg->rlpg_len = rlpg_len;
	rlpg->req_len = req_len;
	rlpg->bitmap_len = bitmap_len;
	rlpg->crc = 0;
	rlpg->nr_lbas = 0;
	rlpg->nr_padded = 0;

	pblk_rlpg_set_bitmaps(rlpg, rblk, nr_entries);

	rblk->cur_sec = 0;
	rblk->nr_invalid_secs = 0;
	rblk->rlpg = rlpg;

	return 0;
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

void pblk_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	complete(waiting);
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

int pblk_fill_partial_read_bio(struct pblk *pblk, struct bio *bio,
			       unsigned long *read_bitmap, struct nvm_rq *rqd,
			       uint8_t nr_secs)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *new_bio;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int nr_holes = nr_secs - bitmap_weight(read_bitmap, nr_secs);
	void *ppa_ptr = NULL;
	dma_addr_t dma_ppa_list = 0;
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
	r_ctx->flags |= PBLK_IOTYPE_SYNC;
	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		ppa_ptr = rqd->ppa_list;
		dma_ppa_list = rqd->dma_ppa_list;
		rqd->ppa_addr = rqd->ppa_list[0];
	}

#ifdef CONFIG_NVM_DEBUG
	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
	if (nvm_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas)) {
		printk(KERN_CRIT "nppas:%d, nr_secs:%d, nr_holes:%d\n",
				rqd->nr_ppas,
				nr_secs,
				nr_holes);
		BUG_ON(1);
	}
		/* WARN_ON(1); */
#endif

	ret = pblk_submit_read_io(pblk, new_bio, rqd, r_ctx->flags);
	wait_for_completion_io(&wait);

	if (bio->bi_error) {
		pr_err("pblk: partial sync read failed (%u)\n", bio->bi_error);
		pblk_print_failed_bio(rqd, rqd->nr_ppas);
	}

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		rqd->ppa_list = ppa_ptr;
		rqd->dma_ppa_list = dma_ppa_list;
	}

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
	pblk_end_io(rqd);
	return NVM_IO_ERR;
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

#define pblk_for_each_lun(pblk, rlun, i) \
		for ((i) = 0, rlun = &(pblk)->luns[0]; \
			(i) < (pblk)->nr_luns; (i)++, rlun = &(pblk)->luns[(i)])

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

static inline void pblk_disable_lun(struct pblk_lun *rlun, struct nvm_lun *lun)
{
	spin_lock(&lun->lock);
	rlun->cur = NULL;
	spin_unlock(&lun->lock);
}

/* Put block back to media manager but do not free rblk structures */
void pblk_retire_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock_lists);
	nvm_put_blk(pblk->dev, rblk->parent);
	list_del(&rblk->list);
	spin_unlock(&rlun->lock_lists);
}

static struct pblk_block *pblk_get_blk(struct pblk *pblk, struct pblk_lun *rlun,
							unsigned long flags)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun = rlun->parent;
	struct nvm_block *blk;
	struct pblk_block *rblk;

try:
	blk = nvm_get_blk(pblk->dev, lun, flags);
	if (!blk) {
		pr_err("pblk: cannot get new block from media manager\n");
		spin_unlock(&lun->lock);
		goto fail_get_blk;
	}

	rblk = pblk_get_rblk(rlun, blk->id);
	blk->priv = rblk;

	if (pblk_init_blk(pblk, rblk, PBLK_BLK_ST_OPEN))
		goto fail_return_blk;

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
		pblk_retire_blk(pblk, rblk);

		goto try;
	}

	return rblk;

fail_return_blk:
	nvm_put_blk(pblk->dev, rblk->parent);
fail_get_blk:
	return NULL;
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

static void pblk_run_blk_ws(struct pblk *pblk, struct pblk_block *rblk,
					void(*work)(struct work_struct *))
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

static void pblk_end_close_blk_bio(struct pblk *pblk, struct nvm_rq *rqd,
				   int run_gc)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_close_ctx *c_ctx = ctx->c_ctx;

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
	mempool_free(rqd, pblk->w_rq_pool);
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
		pblk_run_blk_ws(pblk, rblk, pblk_close_rblk_queue);
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
	ret = pblk_recov_setup_end_rq(pblk, ctx, recovery, comp_bits, c_entries);
	if (ret)
		pr_err("pblk: could not recover from write failure\n");

	pblk_compl_queue(pblk, rqd, ctx);
}

static void pblk_end_io_write(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct pblk_ctx *ctx;

	pblk_ch_semas_up(pblk, rqd);

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
	struct bio *orig_bio = r_ctx->orig_bio;

	if (r_ctx->flags & PBLK_IOTYPE_SYNC)
		return;

	if (nr_secs > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);

	/* TODO: Add this to statistics. Read retry module? */
	if (bio->bi_error) {
		pr_err("pblk: read I/O failed. nr_ppas:%d. Failed:\n", nr_secs);
		pblk_print_failed_bio(rqd, nr_secs);
	}

	bio_put(bio);
	if (orig_bio) {
#ifdef CONFIG_NVM_DEBUG
		BUG_ON(orig_bio->bi_error);
#endif
		bio_endio(orig_bio);
		bio_put(orig_bio);
	}

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


/* The ppa in pblk_addr comes with an offset format, not a global format */
static void pblk_page_pad_invalidate(struct pblk *pblk, struct pblk_block *rblk,
							struct ppa_addr a)
{
	WARN_ON(pblk_gc_invalidate_sec(rblk, a));

	WARN_ON(test_and_set_bit(a.ppa, rblk->sync_bitmap));
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_blk_ws(pblk, rblk, pblk_close_rblk_queue);
}

/* rblk->lock must be taken */
static inline u64 pblk_next_free_sec(struct pblk *pblk, struct pblk_block *rblk)
{
#ifdef CONFIG_NVM_DEBUG
	BUG_ON(rblk->cur_sec >= pblk->nr_blk_dsecs);
#endif

	WARN_ON(test_and_set_bit(rblk->cur_sec, rblk->sector_bitmap));

	return rblk->cur_sec++;
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
			pr_err("pblk: corrupted l2p mapping, blk:%lu,n:%d/%d\n",
					rblk->parent->id,
					i, nr_secs);
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

try_rr:
	rlun = pblk_get_lun_rr(pblk, is_gc);
	lun = rlun->parent;

try_lun:
	/* TODO: This should follow a richer heuristic */
	if (lun->nr_free_blocks < pblk->nr_luns * 4) {
		//XXX: Other?
		printk(KERN_CRIT "NOT SPACE ON LUN\n");
		ret = -ENOSPC;
		goto out;
	}

	spin_lock(&rlun->lock);
	rblk = rlun->cur;

	/* In case the block for the current LUN is being replaced, choose a
	 * different LUN to map the incoming request.
	 */
	if (!rblk) {
		spin_unlock(&rlun->lock);
		goto try_rr;
	}

	/* Account for grown bad blocks */
	if (unlikely(block_is_bad(rblk))) {
		pblk_disable_lun(rlun, lun);
		spin_unlock(&rlun->lock);

		ret = pblk_replace_blk(pblk, rblk, rlun, 1);
		if (ret)
			goto out;

		goto try_lun;
	}

	ret = pblk_map_page(pblk, rblk, sentry, ppa_list, meta_list,
							nr_secs, valid_secs);
	if (ret) {
		spin_unlock(&rlun->lock);
		ret = pblk_replace_blk(pblk, rblk, rlun, 1);
		if (ret)
			goto out;

		goto try_lun;
	}

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(pblk->dev, ppa_list, nr_secs)) {
		u64 gaddr;
		struct ppa_addr p;
		int i;

		printk(KERN_CRIT "FAIL: lun:%u,blk:%lu,n:%u,cur:%lu/%lu\n",
				rlun->parent->id,
				rblk->parent->id,
				nr_secs,
				rblk->cur_sec, rblk->cur_sec - nr_secs);

		for (i = 0; i < nr_secs; i++) {
			gaddr = global_addr(pblk, rblk,
						rblk->cur_sec - nr_secs + i);
			p = pblk_ppa_to_gaddr(pblk->dev, gaddr);
			printk(KERN_CRIT "g:%llu,gen:%llu - ch:%u/%u,pl:%u/%u, "
					"lun:%u/%u,blk:%u/%u,pg:%u/%u,sec:%u/%u\n",
				gaddr,
				p.ppa,
				ppa_list[i].g.ch, p.g.ch,
				ppa_list[i].g.pl, p.g.pl,
				ppa_list[i].g.lun, p.g.lun,
				ppa_list[i].g.blk, p.g.blk,
				ppa_list[i].g.pg, p.g.pg,
				ppa_list[i].g.sec, p.g.sec);
		}

		BUG_ON(1);
	}
		/* WARN_ON(1); */
#endif

	spin_unlock(&rlun->lock);

	/* A page mapping counts as one inflight I/O */
	down(&pblk->ch_list[rlun->ch].ch_sm);

	/* Prepare block for next write */
	if (block_is_full(pblk, rblk)) {
		ret = pblk_replace_blk(pblk, rblk, rlun, 0);
		if (ret)
			goto out;
	}

out:
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

static void pblk_free_blk(struct pblk_block *rblk)
{
	if (rblk->rlpg)
		kfree(rblk->rlpg);
}

void pblk_free_blks(struct pblk *pblk)
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

void pblk_put_blk_unlocked(struct pblk *pblk, struct pblk_block *rblk)
{
	nvm_put_blk(pblk->dev, rblk->parent);
	list_del(&rblk->list);
	pblk_free_blk(rblk);
}

void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock_lists);
	pblk_put_blk_unlocked(pblk, rblk);
	spin_unlock(&rlun->lock_lists);
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


