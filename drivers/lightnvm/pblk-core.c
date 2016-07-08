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

static inline void print_ppa(struct ppa_addr *p, char *msg, int error)
{
	pr_err("ppa: (%s: %x) ch:%d,pl:%d,lun:%d,blk:%d,pg:%d,sec:%d\n",
		msg, error,
		p->g.ch, p->g.pl, p->g.lun, p->g.blk, p->g.pg, p->g.sec);
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

/*
 * There is no guarantee that the value read from cache has not been updated. In
 * order to guarantee that writes and reads are ordered, a flush must be issued
 */
void pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
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

int pblk_read_rq(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
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

int pblk_submit_read_io(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
			unsigned long flags)
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

void pblk_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	complete(waiting);
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
	if (nvm_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
		WARN_ON(1);
#endif

	ret = pblk_submit_read_io(pblk, new_bio, rqd, r_ctx->flags);
	wait_for_completion_io(&wait);

	if (bio->bi_error) {
		inc_stat(pblk, &pblk->read_failed);
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

	ctx_bio = (bio->bi_rw & REQ_PREFLUSH) ? bio : NULL;
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
static int pblk_write_to_cache(struct pblk *pblk, struct bio *bio,
			       unsigned long flags, unsigned int nr_entries)
{
	sector_t laddr = pblk_get_laddr(bio);
	struct bio *ctx_bio = (bio->bi_rw & REQ_PREFLUSH) ? bio : NULL;
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
		pblk->write_cur_speed = PBLK_USER_MAX_SPEED;
	else if (avail > low && avail < high)
	{
		/* redo to power of two calculations */
		int perc = ((avail * 100)) / (high - low);
		pblk->write_cur_speed = (PBLK_USER_MAX_SPEED / 100) * perc;
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

int pblk_buffer_write(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	int nr_secs = pblk_get_secs(bio);
	int ret = NVM_IO_DONE;

	if (bio->bi_rw & REQ_PREFLUSH) {
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

	ret = pblk_write_to_cache(pblk, bio, flags, nr_secs);
	if (ret == NVM_IO_REQUEUE)
		goto retry;

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
	if (bio->bi_rw & REQ_PREFLUSH)
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
	bio->bi_rw = REQ_OP_WRITE | REQ_PREFLUSH;
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_sync_bio;

	ret = pblk_buffer_write(pblk, bio, 0);
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
	if (nvm_erase_blk(dev, rblk->parent, pblk_set_progr_mode(pblk))) {
		struct ppa_addr ppa;

		/* Mark block as bad and return it to media manager */
		ppa = pblk_ppa_to_gaddr(dev, block_to_addr(pblk, rblk));
		nvm_mark_blk(dev, ppa, NVM_BLK_ST_BAD);
		pblk_retire_blk(pblk, rblk);

		inc_stat(pblk, &pblk->erase_failed);
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

static void pblk_end_io_write(struct pblk *pblk, struct nvm_rq *rqd)
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

	if (bio->bi_error) {
		inc_stat(pblk, &pblk->read_failed);
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

void pblk_end_io(struct nvm_rq *rqd)
{
	struct pblk *pblk = container_of(rqd->ins, struct pblk, instance);
	uint8_t nr_secs = rqd->nr_ppas;

	if (rqd->bio->bi_rw == READ)
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
		bio->bi_rw = WRITE;
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

int pblk_alloc_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
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

