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
 *
 * pblk-read.c - 
 */

#include "pblk.h"

static void pblk_setup_seq_reads(struct pblk *pblk, struct ppa_addr *ppas,
				sector_t bladdr, int nr_secs)
{
	struct pblk_addr *gp;
	int i;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++) {
		gp = &pblk->trans_map[bladdr + i];
		ppas[i] = gp->ppa;
	}
	spin_unlock(&pblk->trans_lock);
}

static void pblk_setup_rand_reads(struct pblk *pblk, struct ppa_addr *ppas,
				 u64 *lba_list, int nr_secs)
{
	struct pblk_addr *gp;
	sector_t lba;
	int i;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++) {
		lba = lba_list[i];
		if (lba == ADDR_EMPTY)
			continue;

		gp = &pblk->trans_map[lba];
		ppas[i] = gp->ppa;
	}
	spin_unlock(&pblk->trans_lock);
}

/*
 * There is no guarantee that the value read from cache has not been updated. In
 * order to guarantee that writes and reads are ordered, a flush must be issued
 */
static void pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
				 struct ppa_addr ppa)
{
	pblk_rb_copy_to_bio(&pblk->rwb, bio, nvm_addr_to_cacheline(ppa));
}

static int pblk_try_read_from_cache(struct pblk *pblk, struct bio *bio,
				    struct ppa_addr ppa)
{
	/* The write thread commits the changes to the buffer once the l2p table
	 * has been updated. In this way, if the address read from the l2p table
	 * points to a cacheline, the lba lock guarantees that the entry is not
	 * going to be updated by new writes
	 */
	if (!nvm_addr_in_cache(ppa))
		return 0;

	pblk_read_from_cache(pblk, bio, ppa);
	return 1;
}

static int pblk_read_ppalist_rq(struct pblk *pblk, struct bio *bio,
				struct nvm_rq *rqd, unsigned long flags,
				int nr_secs, unsigned long *read_bitmap)
{
	sector_t laddr = pblk_get_laddr(bio);
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	int advanced_bio = 0;
	int i, j = 0;

	BUG_ON(!(laddr >= 0 && laddr + nr_secs < pblk->nr_secs));

	pblk_setup_seq_reads(pblk, ppas, laddr, nr_secs);

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

static int pblk_submit_read_io(struct pblk *pblk, struct bio *bio,
			       struct nvm_rq *rqd, unsigned long flags)
{
	int err;

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

static int pblk_fill_partial_read_bio(struct pblk *pblk, struct bio *bio,
				      unsigned long *read_bitmap,
				      struct nvm_rq *rqd, uint8_t nr_secs)
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
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
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
	if (nvm_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
		WARN_ON(1);
#endif

	ret = pblk_submit_read_io(pblk, new_bio, rqd, r_ctx->flags);
	wait_for_completion_io(&wait);

	if (bio->bi_error) {
		inc_stat(pblk, &pblk->read_failed, 0);
		pblk_print_failed_rqd(pblk, rqd, bio->bi_error);
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

		mempool_free(src_p, pblk->page_pool);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

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


static int __pblk_submit_read(struct pblk *pblk, struct nvm_rq *rqd,
			      struct bio *bio, unsigned long *read_bitmap,
			      int flags, int nr_secs, int clone_read)
{
	int ret = NVM_IO_OK;

	if (bitmap_empty(read_bitmap, nr_secs)) {
		struct bio *int_bio = NULL;
#ifdef CONFIG_NVM_DEBUG
		struct ppa_addr *ppa_list;

		ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
		if (nvm_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
			WARN_ON(1);
#endif

		if (clone_read) {
			struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);

			/* Clone read bio to deal with read errors internally */
			int_bio = bio_clone_bioset(bio, GFP_KERNEL, fs_bio_set);
			if (!int_bio) {
				pr_err("pblk: could not clone read bio\n");
				goto fail_ppa_free;
			}

			rqd->bio = int_bio;
			r_ctx->orig_bio = bio;
		}

		ret = pblk_submit_read_io(pblk, int_bio, rqd, flags);
		if (ret) {
			pr_err("pblk: read IO submission failed\n");
			if (int_bio)
				bio_put(int_bio);
			goto fail_ppa_free;
		}

		return NVM_IO_OK;
	}

	/* The read bio request could be partially filled by the write buffer,
	 * but there are some holes that need to be read from the drive.
	 */
	ret = pblk_fill_partial_read_bio(pblk, bio, read_bitmap, rqd, nr_secs);
	if (ret) {
		pr_err("pblk: failed to perform partial read\n");
		goto fail_ppa_free;
	}

	return NVM_IO_OK;

fail_ppa_free:
	if ((nr_secs > 1) && (!(flags & PBLK_IOTYPE_GC)))
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);
	return ret;
}

static int pblk_read_rq(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
			sector_t laddr, unsigned long *read_bitmap,
			unsigned long flags)
{
	struct pblk_addr *gp;
	struct ppa_addr ppa;
	int ret = NVM_IO_OK;

	if (laddr == ADDR_EMPTY) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		ret = NVM_IO_DONE;
		goto out;
	}

	BUG_ON(!(laddr >= 0 && laddr < pblk->nr_secs));

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];
	ppa = gp->ppa;
	spin_unlock(&pblk->trans_lock);

	if (ppa_empty(ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		return NVM_IO_DONE;
	}

	if (pblk_try_read_from_cache(pblk, bio, ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		return NVM_IO_DONE;
	}

	rqd->ppa_addr = ppa;

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_reads);
#endif
	return NVM_IO_OK;
out:
	return ret;
}

int pblk_submit_read(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	struct nvm_rq *rqd;
	struct pblk_r_ctx *r_ctx;
	unsigned long read_bitmap; /* Max 64 ppas per request */
	int nr_secs = pblk_get_secs(bio);
	int ret = NVM_IO_ERR;

	if (nr_secs != bio->bi_vcnt)
		return NVM_IO_ERR;

	bitmap_zero(&read_bitmap, nr_secs);

	rqd = pblk_alloc_rqd(pblk, READ);
	if (IS_ERR(rqd)) {
		pr_err_ratelimited("pblk: not able to alloc rqd");
		bio_io_error(bio);
		return NVM_IO_ERR;
	}
	r_ctx = nvm_rq_to_pdu(rqd);

	if (nr_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
						&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			goto fail_rqd_free;
		}

		pblk_read_ppalist_rq(pblk, bio, rqd, flags, nr_secs,
								&read_bitmap);
	} else {
		sector_t laddr = pblk_get_laddr(bio);

		ret = pblk_read_rq(pblk, bio, rqd, laddr, &read_bitmap, flags);
		if (ret)
			goto fail_rqd_free;
	}

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = nr_secs;
	r_ctx->flags = flags;

	bio_get(bio);
	if (bitmap_full(&read_bitmap, nr_secs)) {
		bio_endio(bio);
		pblk_end_io(rqd);
		return NVM_IO_OK;
	}

	return __pblk_submit_read(pblk, rqd, bio, &read_bitmap, flags,
								nr_secs, 1);

fail_rqd_free:
	pblk_free_rqd(pblk, rqd, READ);
	return ret;
}

static int read_ppalist_rq_list(struct pblk *pblk, struct bio *bio,
				struct nvm_rq *rqd, u64 *lba_list,
				unsigned int nr_secs,
				unsigned long *read_bitmap, unsigned long flags)
{
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	sector_t lba;
	int advanced_bio = 0;
	int valid_secs = 0;
	int i, j = 0;

	pblk_setup_rand_reads(pblk, ppas, lba_list, nr_secs);

	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr *p = &ppas[i];

		lba = lba_list[i];

		if (lba == ADDR_EMPTY)
			continue;

		if (ppa_empty(*p))
			continue;

		BUG_ON(!(lba >= 0 && lba < pblk->nr_secs));

		/* Try to read from write buffer. Those addresses that cannot be
		 * read from the write buffer are sequentially added to the ppa
		 * list, which will later on be used to submit an I/O to the
		 * device to retrieve data.
		 */
		if (nvm_addr_in_cache(*p)) {
			WARN_ON(test_and_set_bit(valid_secs, read_bitmap));
			if (unlikely(!advanced_bio)) {
				/* This is at least a partially filled bio,
				 * advance it to copy data to the right place.
				 * We will deal with partial bios later on.
				 */
				bio_advance(bio, valid_secs *
							PBLK_EXPOSED_PAGE_SIZE);
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

		valid_secs++;

		if (advanced_bio)
			bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
		atomic_add(nr_secs, &pblk->inflight_reads);
#endif
	return valid_secs;
}

int pblk_submit_read_list(struct pblk *pblk, struct bio *bio,
			  struct nvm_rq *rqd, u64 *lba_list,
			  unsigned int nr_secs, unsigned int nr_rec_secs,
			  unsigned long flags)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	unsigned long read_bitmap; /* Max 64 ppas per request */
	unsigned int valid_secs = 1;
	int ret;

	if (nr_rec_secs != bio->bi_vcnt)
		return NVM_IO_ERR;

	bitmap_zero(&read_bitmap, nr_secs);

	if (nr_rec_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
						  &rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			return NVM_IO_ERR;
		}

		valid_secs = read_ppalist_rq_list(pblk, bio, rqd, lba_list,
						  nr_secs, &read_bitmap, flags);
	} else {
		sector_t laddr = lba_list[0];

		ret = pblk_read_rq(pblk, bio, rqd, laddr, &read_bitmap, flags);
		if (ret)
			return ret;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_rec_secs != valid_secs);
#endif

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = valid_secs;
	r_ctx->flags = flags;

	if (bitmap_full(&read_bitmap, valid_secs)) {
		bio_endio(bio);
		return NVM_IO_OK;
	}

	return __pblk_submit_read(pblk, rqd, bio, &read_bitmap, flags,
								valid_secs, 0);
}

void pblk_end_io_read(struct pblk *pblk, struct nvm_rq *rqd, uint8_t nr_secs)
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

	if (bio->bi_error) {
		inc_stat(pblk, &pblk->read_failed, 1);
		pblk_print_failed_rqd(pblk, rqd, bio->bi_error);
	}

	bio_put(bio);
	if (orig_bio) {
#ifdef CONFIG_NVM_DEBUG
		BUG_ON(orig_bio->bi_error);
#endif
		bio_endio(orig_bio);
		bio_put(orig_bio);
	}

	pblk_free_rqd(pblk, rqd, READ);

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_secs, &pblk->sync_reads);
	atomic_sub(nr_secs, &pblk->inflight_reads);
#endif
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
	struct pblk_ctx *ctx;

	if (rqd->error == NVM_RSP_ERR_FAILWRITE)
		return pblk_end_w_fail(pblk, rqd);

	ctx = pblk_set_ctx(pblk, rqd);

	if (ctx->flags & PBLK_IOTYPE_SYNC)
		return;

	if (ctx->flags & PBLK_IOTYPE_CLOSE_BLK)
		return pblk_end_close_blk_bio(pblk, rqd, 1);

	pblk_compl_queue(pblk, rqd, ctx);
	/*pblk_write_kick(pblk);*/
}

