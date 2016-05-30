/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
 * Copyright (C) 2016 CNEX Labs
 * Initial: Javier Gonzalez <jg@lightnvm.io>
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
 */

#include "pblk.h"
#include "pblk-recovery.h"
#include "pblk-gc.h"

extern unsigned long pblk_r_rq_size, pblk_w_rq_size;

/*
 * Write Retry - These set of functions implement recovery mechanisms for a
 * failed write.
 */

static void pblk_rec_valid_pgs(struct work_struct *work)
{
	struct pblk_block_gc *gcb = container_of(work, struct pblk_block_gc,
									ws_gc);
	struct pblk *pblk = gcb->pblk;
	struct pblk_block *rblk = gcb->rblk;
	struct pblk_blk_rec_lpg *rlpg = rblk->rlpg;
	u64 *lba_list = pblk_rlpg_to_llba(rlpg);
	unsigned int nr_entries;
	int off;
	int try = 0;
	int ret;

	/* Prevent recovering a block that is being mapped by the writing
	 * thread, even though we know it is a grown bad block.
	 */
	spin_lock(&rblk->lock);
	nr_entries = bitmap_weight(rblk->pages, pblk->nr_blk_dsecs);

	/* Recovery for this block already in progress */
	if (nr_entries == 0) {
		spin_unlock(&rblk->lock);
		goto out;
	}

	/* Clear mapped pages as they are set for recovery */
	off = find_first_bit(rblk->pages, pblk->nr_blk_dsecs);
	bitmap_clear(rblk->pages, off, nr_entries);
	spin_unlock(&rblk->lock);

retry:
	ret = pblk_gc_move_valid_pages(pblk, rblk, &lba_list[off], nr_entries);
	if (ret != nr_entries) {
		pr_err("pblk: could not recover all pages:blk:%lu, "
						"recovered:%d/%d. Try:%d/%d\n",
						rblk->parent->id,
						ret, nr_entries,
						try, PBLK_GC_TRIES);
		if (try < PBLK_GC_TRIES) {
			off += ret;
			goto retry;
		} else {
			pr_err("pblk: recovery failed\n");
		}
	}

	spin_lock(&rblk->rlun->lock_lists);
	list_move_tail(&rblk->list, &rblk->rlun->bb_list);
	spin_unlock(&rblk->rlun->lock_lists);

	/*
	 * TODO: Clean bb_list when doing GC
	 */

	mempool_free(gcb, pblk->gcb_pool);
	return;
out:
	mempool_free(gcb, pblk->gcb_pool);
}

static int pblk_setup_rec_rq(struct pblk *pblk, struct nvm_rq *rqd,
			struct pblk_ctx *ctx, unsigned int nr_rec_secs)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	unsigned int nr_secs = valid_secs + padded_secs;
	unsigned int setup_secs;
	struct pblk_sec_meta *meta;
	int min = pblk->min_write_pgs;
	int i;
	int ret = 0;

	ret = pblk_alloc_w_rq(pblk, rqd, ctx, nr_rec_secs);
	if (ret)
		goto out;

	meta = rqd->meta_list;

	if (unlikely(nr_rec_secs == 1)) {
		BUG_ON(nr_secs != 1);
		BUG_ON(padded_secs != 0);
		ret = pblk_setup_w_single(pblk, rqd, ctx, meta);
		goto out;
	}

	/* TODO: Use mask to check that a whole page fails (not indiv. secs) */
	for (i = 0; i < nr_rec_secs; i += min) {
		if (i + min > nr_rec_secs) {
			setup_secs = nr_rec_secs % min;

			if (c_ctx->nr_valid == 0) {
				c_ctx->nr_padded -= min;
			} else if (c_ctx->nr_valid >= min) {
				c_ctx->nr_valid -= min;
			} else {
				c_ctx->nr_padded -= min - c_ctx->nr_valid;
				c_ctx->nr_valid = 0;
			}
		}

		setup_secs = (i + min > nr_rec_secs) ?
						(nr_rec_secs % min) : min;
		ret = pblk_setup_w_multi(pblk, rqd, ctx, meta, setup_secs, i);
	}

	rqd->ppa_status = (u64)0;

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(dev, rqd->ppa_list, rqd->nr_ppas))
		BUG_ON(1);
		/* WARN_ON(1); */
#endif

out:
	return ret;
}

/* pblk_submit_rec -- thread to submit recovery requests
 *
 * When a write request fails, rqd->ppa_status signals which specific ppas could
 * not be written to the media. All ppas previous to the failed writes could be
 * completed when the io finished, as part of the end_io recovery. However,
 * successful writes after the failed ppas are not completed in order to
 * maintain the consistency of the back pointer that guarantees sequentiality on
 * the write buffer.
 */
static void pblk_submit_rec(struct work_struct *work)
{
	struct pblk_rec_ctx *recovery =
			container_of(work, struct pblk_rec_ctx, ws_rec);
	struct pblk *pblk = recovery->pblk;
	struct nvm_dev *dev = pblk->dev;
	struct nvm_rq *rqd = recovery->rqd;
	struct bio *bio;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	unsigned int nr_rec_secs;
	unsigned int pgs_read;
	int max_secs = dev->ops->max_phys_sect;
	int err;

	nr_rec_secs =
		bitmap_weight((long unsigned int *)&rqd->ppa_status, max_secs);

	bio = bio_alloc(GFP_KERNEL, nr_rec_secs);
	if (!bio) {
		pr_err("pblk: not able to create recovery bio\n");
		return;
	}
	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio->bi_rw = WRITE;
	rqd->bio = bio;

	pgs_read = pblk_rb_read_to_bio_list(&pblk->rwb, bio, ctx,
					&recovery->failed, nr_rec_secs);
	if (pgs_read != nr_rec_secs) {
		pr_err("pblk: could not read recovery entries\n");
		goto fail;
	}

	if (pblk_setup_rec_rq(pblk, rqd, ctx, nr_rec_secs)) {
		pr_err("pblk: could not setup recovery request\n");
		goto fail;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_rec_secs, &pblk->recov_writes);
#endif

	err = nvm_submit_io(dev, rqd);
	if (err) {
		pr_err("pblk: I/O submission failed: %d\n", err);
		goto fail;
	}

	mempool_free(recovery, pblk->rec_pool);
	return;

fail:
	bio_put(bio);
	mempool_free(rqd, pblk->w_rq_pool);
}

void pblk_run_recovery(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_block_gc *gcb;

	gcb = mempool_alloc(pblk->gcb_pool, GFP_ATOMIC);
	if (!gcb) {
		pr_err("pblk: unable to queue block for recovery gc.");
		return;
	}

	gcb->pblk = pblk;
	gcb->rblk = rblk;

	/* Move data from grown bad block */
	INIT_WORK(&gcb->ws_gc, pblk_rec_valid_pgs);
	queue_work(pblk->kgc_wq, &gcb->ws_gc);
}

int pblk_setup_rec_end_rq(struct pblk *pblk, struct pblk_ctx *ctx,
			  struct pblk_rec_ctx *recovery, u64 *comp_bits,
			  unsigned int c_entries)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct nvm_rq *rec_rqd;
	struct pblk_ctx *rec_ctx;
	struct pblk_compl_ctx *rec_c_ctx;
	int max_secs = pblk->dev->ops->max_phys_sect;
	int nr_entries = c_ctx->nr_valid + c_ctx->nr_padded;

	rec_rqd = mempool_alloc(pblk->w_rq_pool, GFP_ATOMIC);
	if (!rec_rqd) {
		pr_err("pblk: could not create recovery req.\n");
		return -ENOMEM;
	}
	memset(rec_rqd, 0, pblk_w_rq_size);
	rec_ctx = pblk_set_ctx(pblk, rec_rqd);
	rec_c_ctx = rec_ctx->c_ctx;

	/* Copy completion bitmap, but exclude the first X completed entries */
	bitmap_shift_right((long unsigned int *)&rec_rqd->ppa_status,
				(long unsigned int *)comp_bits,
				c_entries, max_secs);

	/* Save the context for the entries that need to be re-written and
	 * update current context with the completed entries.
	 */
	rec_c_ctx->sentry = pblk_rb_wrap_pos(&pblk->rwb,
						c_ctx->sentry + c_entries);
	if (c_entries >= c_ctx->nr_valid) {
		/* Recovery context */
		rec_c_ctx->nr_valid = 0;
		rec_c_ctx->nr_padded = nr_entries - c_entries;

		/* Updated completion context */
		c_ctx->nr_padded = c_entries - c_ctx->nr_valid;
	} else {
		/* Recovery context */
		rec_c_ctx->nr_valid = c_ctx->nr_valid - c_entries;
		rec_c_ctx->nr_padded = c_ctx->nr_padded;

		/* Updated completion context */
		c_ctx->nr_valid = c_entries;
		c_ctx->nr_padded = 0;
	}

	rec_ctx->flags = ctx->flags;
	recovery->rqd = rec_rqd;
	recovery->pblk = pblk;

	INIT_WORK(&recovery->ws_rec, pblk_submit_rec);
	queue_work(pblk->kw_wq, &recovery->ws_rec);

	return 0;
}

/*
 * Bring up & tear down scanning - These set of functions implement "last page
 * recovery". This is, saving the l2p mapping of each block on the last page to
 * be able to reconstruct the l2p table by scanning the last page of each block.
 * This mechanism triggers when l2p snapshot fails
 */

/* Read last page on block and update l2p table if necessary */
int pblk_scan_recover_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_blk_rec_lpg *rlpg;
	struct pblk_r_ctx *r_ctx;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *bio_data;
	struct ppa_addr ppa_addr[PBLK_RECOVERY_SECTORS];
	struct ppa_addr ppa;
	u64 *lba_list;
	u64 bppa, rppa;
	u32 rlpg_len;
	u32 crc = ~(u32)0;
	unsigned int bio_len = dev->sec_per_pl * dev->sec_size;
	int i;
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(wait);

	bio_data = kzalloc(bio_len, GFP_KERNEL);
	if (!bio_data) {
		pr_err("pblk: could not allocate recovery ppa list\n");
		return -1;
	}

	bio = bio_map_kern(dev->q, bio_data, bio_len, GFP_KERNEL);
	if (!bio) {
		pr_err("pblk: could not allocate recovery bio\n");
		ret = -1;
		goto free_bio_data;
	}

	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd) {
		pr_err("pblk: not able to create write req.\n");
		ret = -1;
		goto free_bio;
	}
	memset(rqd, 0, pblk_r_rq_size);

	bio->bi_iter.bi_sector = 0;
	bio->bi_rw = READ;
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_sync_bio;

	rqd->opcode = NVM_OP_PREAD;
	rqd->ins = &pblk->instance;
	rqd->bio = bio;
	rqd->meta_list = NULL;
	rqd->flags = NVM_IO_SNGL_ACCESS | NVM_IO_SUSPEND;

	r_ctx = nvm_rq_to_pdu(rqd);
	r_ctx->flags = PBLK_IOTYPE_SYNC;

	/* Last page in block contains mapped lba list if block is closed */
	for (i = 0; i < PBLK_RECOVERY_SECTORS; i++) {
		rppa = pblk->nr_blk_dsecs + i;
		ppa_addr[i] = pblk_ppa_to_gaddr(dev,
					global_addr(pblk, rblk, rppa));
	}

	if (nvm_set_rqd_ppalist(dev, rqd, ppa_addr, PBLK_RECOVERY_SECTORS, 1)) {
		pr_err("pblk: not able to set rqd ppa list\n");
		ret = -1;
		goto free_rqd;
	}

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(dev, rqd->ppa_list, rqd->nr_ppas))
		BUG_ON(1);
		/* WARN_ON(1); */
#endif

	if (nvm_submit_io(dev, rqd)) {
		pr_err("pblk: I/O submission failed\n");
		ret = -1;
		nvm_free_rqd_ppalist(dev, rqd);
		goto free_rqd;
	}
	wait_for_completion_io(&wait);

	rlpg = bio_data;

	rlpg_len = sizeof(struct pblk_blk_rec_lpg) +
					(pblk->nr_blk_dsecs * sizeof(u64));
	crc = cpu_to_le32(crc32_le(crc, (unsigned char *)rlpg + sizeof(crc),
						rlpg_len - sizeof(crc)));

	if (rlpg->crc != crc || rlpg->status != PBLK_BLK_ST_CLOSED)
		goto free_rqd;

	bppa = global_addr(pblk, rblk, 0);
	lba_list = pblk_rlpg_to_llba(rlpg);
	/* TODO: We need gennvm to give us back the blocks that we owe so that
	 * we can bring up the data structures before we populate them
	 *  - all bitmaps
	 *  - GC
	 */
	for (i = 0; i < pblk->nr_blk_dsecs; i++) {
		ppa = addr_to_ppa(bppa + i);
		if (lba_list[i] != ADDR_EMPTY)
			pblk_update_map(pblk, lba_list[i], rblk, ppa);
		/*else - mark as invalid */
	}

free_rqd:
	mempool_free(rqd, pblk->r_rq_pool);
free_bio:
	bio_put(bio);
free_bio_data:
	kfree(bio_data);

	return ret;
}

/*
 * The current block is out of the fast path; no more data can be written to it.
 * Save the list of the lbas stored in the block on the last page of the block.
 * This is used for GC and for recovery in case of FTL corruption after a crash.
 */
static void pblk_close_rblk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_rq *rqd;
	struct pblk_ctx *ctx;
	struct pblk_compl_close_ctx *c_ctx;
	struct bio *bio;
	struct ppa_addr ppa_addr[PBLK_RECOVERY_SECTORS];
	int nr_entries = pblk->nr_blk_dsecs;
	int rqd_len;
	u32 crc = ~(u32)0;
	u64 paddr;
	int i;

#ifdef CONFIG_NVM_DEBUG
	if (!block_is_bad(rblk))
		BUG_ON(rblk->rlpg->nr_lbas + rblk->rlpg->nr_padded !=
								nr_entries);
#endif

	rblk->rlpg->status = PBLK_BLK_ST_CLOSED;
	crc = crc32_le(crc, (unsigned char *)rblk->rlpg + sizeof(crc),
					rblk->rlpg->rlpg_len - sizeof(crc));
	rblk->rlpg->crc = cpu_to_le32(crc);

	bio = bio_map_kern(dev->q, rblk->rlpg, rblk->rlpg->req_len, GFP_KERNEL);
	if (!bio) {
		pr_err("pblk: could not allocate recovery bio\n");
		return;
	}

	rqd_len = sizeof(struct nvm_rq) + sizeof(struct pblk_ctx) +
					sizeof(struct pblk_compl_close_ctx);
	rqd = kzalloc(rqd_len, GFP_KERNEL);
	if (!rqd) {
		pr_err("pblk: not able to create write req.\n");
		goto fail_alloc_rqd;
	}
	memset(rqd, 0, rqd_len);
	ctx = pblk_set_ctx(pblk, rqd);
	ctx->flags = PBLK_IOTYPE_CLOSE_BLK;
	c_ctx = ctx->c_ctx;
	c_ctx->rblk = rblk;

	bio_get(bio);
	bio->bi_iter.bi_sector = 0;
	bio->bi_rw = WRITE;

	rqd->opcode = NVM_OP_PWRITE;
	rqd->ins = &pblk->instance;
	rqd->bio = bio;
	rqd->meta_list = NULL;

	/* address within a block for the last writable page */
	for (i = 0; i < PBLK_RECOVERY_SECTORS; i++) {
		paddr = nr_entries + i;
		ppa_addr[i] = pblk_ppa_to_gaddr(dev,
					global_addr(pblk, rblk, paddr));
	}

	if (nvm_set_rqd_ppalist(dev, rqd, ppa_addr, PBLK_RECOVERY_SECTORS, 1)) {
		pr_err("pblk: not able to set rqd ppa list\n");
		goto fail_set_rqd;
	}

#ifdef CONFIG_NVM_DEBUG
	if (nvm_boundary_checks(dev, rqd->ppa_list, rqd->nr_ppas))
		BUG_ON(1);
		/* WARN_ON(1); */
#endif

	if (nvm_submit_io(dev, rqd)) {
		pr_err("pblk: I/O submission failed\n");
		goto fail_submit;
	}

	return;

fail_submit:
	nvm_free_rqd_ppalist(dev, rqd);
fail_set_rqd:
	kfree(rqd);
fail_alloc_rqd:
	bio_put(bio);
}

void pblk_close_rblk_queue(struct work_struct *work)
{
	struct pblk_block_gc *gcb = container_of(work, struct pblk_block_gc,
									ws_gc);
	struct pblk *pblk = gcb->pblk;
	struct pblk_block *rblk = gcb->rblk;

	if (likely(!block_is_bad(rblk)))
		pblk_close_rblk(pblk, rblk);

	kfree(rblk->sync_bitmap);
	rblk->sync_bitmap = NULL;
	mempool_free(gcb, pblk->gcb_pool);
}


