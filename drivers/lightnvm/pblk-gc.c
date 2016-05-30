/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Matias Bjorling <m@bjorling.me>
 *		  : Javier Gonzalez <jg@lightnvm.io>
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

extern unsigned long pblk_r_rq_size, pblk_w_rq_size;

static void pblk_free_gc_rqd(struct pblk *pblk, struct nvm_rq *rqd)
{
	uint8_t nr_secs = rqd->nr_ppas;

	if (nr_secs > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);

	mempool_free(rqd, pblk->r_rq_pool);
}

static int pblk_write_list_to_cache(struct pblk *pblk, struct bio *bio,
				      unsigned long flags, u64 *lba_list,
				      struct pblk_kref_buf *ref_buf,
				      unsigned int nr_secs,
				      unsigned int nr_rec_secs, int *ret_val)
{
	struct pblk_w_ctx w_ctx;
	struct ppa_addr ppa;
	void *data;
	struct bio *b = NULL;
	unsigned long pos;
	unsigned int i, valid_secs = 0;

	BUG_ON(!bio_has_data(bio) || (nr_rec_secs != bio->bi_vcnt));

	pblk_rb_write_init(&pblk->rwb);

	if (pblk_rb_space(&pblk->rwb) < nr_secs)
		goto rollback;

	if (pblk_rb_update_l2p(&pblk->rwb, nr_secs))
		goto rollback;

	pos = pblk_rb_write_pos(&pblk->rwb);

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		b = bio;
		*ret_val = NVM_IO_OK;
	} else {
		b = NULL;
		*ret_val = NVM_IO_DONE;
	}

	for (i = 0, valid_secs = 0; i < nr_secs; i++) {
		if (lba_list[i] == ADDR_EMPTY)
			continue;

		w_ctx.bio = b;
		w_ctx.lba = lba_list[i];
		w_ctx.flags = flags;
		ppa_set_empty(&w_ctx.ppa.ppa);

#ifdef CONFIG_NVM_DEBUG
		BUG_ON(!(flags & PBLK_IOTYPE_REF));
#endif
		w_ctx.priv = ref_buf;
		kref_get(&ref_buf->ref);

		data = bio_data(bio);
		if (pblk_rb_write_entry(&pblk->rwb, data, w_ctx,
							pos + valid_secs))
			goto rollback;

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
		valid_secs++;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_rec_secs != valid_secs);
#endif

	/* Update mapping table with the write buffer cachelines. Do it after
	 * the data is written to the buffer to enable atomic rollback
	 */
	for (i = 0, valid_secs = 0; i < nr_secs; i++) {
		if (lba_list[i] == ADDR_EMPTY)
			continue;

		ppa = pblk_cacheline_to_ppa(
				pblk_rb_wrap_pos(&pblk->rwb, pos + valid_secs));
		pblk_update_map(pblk, lba_list[i], NULL, ppa);
		valid_secs++;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(valid_secs, &pblk->inflight_writes);
	atomic_add(valid_secs, &pblk->recov_gc_writes);
#endif

	pblk_rb_write_commit(&pblk->rwb, valid_secs);
	return 1;

rollback:
	pblk_rb_write_rollback(&pblk->rwb);
	return 0;
}

static int pblk_read_ppalist_rq_list(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, u64 *lba_list,
			unsigned int nr_secs, unsigned int *valid_secs,
			unsigned long flags, unsigned long *read_bitmap)
{
	/* int is_gc = *flags & PBLK_IOTYPE_GC; */
	/* int locked = 0; */
	sector_t lba;
	int advanced_bio = 0;
	int i, j = 0;
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];

	(*valid_secs) = 0;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++) {
		lba = lba_list[i];

		if (lba == ADDR_EMPTY)
			continue;

		ppas[i] = pblk->trans_map[lba].ppa;
	}
	spin_unlock(&pblk->trans_lock);

	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr *p = &ppas[i];

		lba = lba_list[i];

		if (lba == ADDR_EMPTY)
			continue;

		if (ppa_empty(*p))
			continue;

		BUG_ON(!(lba >= 0 && lba < pblk->nr_secs));

		(*valid_secs)++;

		/* Try to read from write buffer. Those addresses that cannot be
		 * read from the write buffer are sequentially added to the ppa
		 * list, which will later on be used to submit an I/O to the
		 * device to retrieve data.
		 */
		if (nvm_addr_in_cache(*p)) {
			WARN_ON(test_and_set_bit(*valid_secs, read_bitmap));
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

static int pblk_submit_read_list(struct pblk *pblk, struct bio *bio,
				   struct nvm_rq *rqd, u64 *lba_list,
				   unsigned int nr_secs,
				   unsigned int nr_rec_secs,
				   unsigned long flags)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	unsigned long read_bitmap; /* Max 64 ppas per request */
	unsigned int valid_secs = 1;
	int ret;

	bitmap_zero(&read_bitmap, nr_secs);

	rqd->meta_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
							&rqd->dma_meta_list);
	if (!rqd->meta_list) {
		pr_err("pblk: not able to allocate metadata list\n");
		return NVM_IO_ERR;
	}

	if (nr_rec_secs != bio->bi_vcnt)
		return NVM_IO_ERR;

	if (nr_rec_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
						&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			ret = NVM_IO_ERR;
			goto fail_meta_free;
		}

		ret = pblk_read_ppalist_rq_list(pblk, bio, rqd, lba_list,
						nr_secs, &valid_secs, flags,
						&read_bitmap);
		if (ret)
			goto fail_ppa_free;
	} else {
		ret = pblk_read_rq(pblk, bio, rqd, lba_list[0], flags,
								&read_bitmap);
		if (ret)
			goto fail_meta_free;
	}

	bio_get(bio);
	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = valid_secs;
	r_ctx->flags = flags;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_rec_secs != valid_secs);
#endif

	if (bitmap_full(&read_bitmap, valid_secs)) {
		bio_endio(bio);
		pblk_end_io(rqd);
		return NVM_IO_OK;
	} else if (bitmap_empty(&read_bitmap, valid_secs)) {
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
								valid_secs);
	if (ret) {
		pr_err("pblk: failed to perform partial read\n");
		goto fail_ppa_free;
	}

	return NVM_IO_OK;

fail_ppa_free:
	if ((nr_rec_secs > 1) && (!(flags & PBLK_IOTYPE_GC)))
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);
fail_meta_free:
	nvm_dev_dma_free(pblk->dev, rqd->meta_list, rqd->dma_meta_list);
	return ret;
}

/*
 * pblk_move_valid_pages -- migrate live data off the block
 * @pblk: the 'pblk' structure
 * @block: the block from which to migrate live pages
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
int pblk_gc_move_valid_pages(struct pblk *pblk, struct pblk_block *rblk,
			     u64 *lba_list, unsigned int nr_entries)
{
	struct nvm_dev *dev = pblk->dev;
	struct request_queue *q = dev->q;
	struct nvm_rq *rqd;
	struct pblk_addr *gp;
	struct bio *bio;
	struct pblk_kref_buf *ref_buf;
	void *data;
	u64 lba;
	unsigned int bio_len;
	unsigned int alloc_entries, secs_to_gc, secs_in_disk;
	unsigned int read_left, ignored;
	int max = pblk->max_write_pgs;
	int i, off;
	int ret, moved = 0;
	DECLARE_COMPLETION_ONSTACK(wait);

	alloc_entries = (nr_entries > max) ? max : nr_entries;
	data = kmalloc(alloc_entries * dev->sec_size, GFP_KERNEL);
	if (!data) {
		pr_err("pblk: could not allocate GC buffer\n");
		goto out;
	}

	ref_buf = kmalloc(sizeof(struct pblk_kref_buf), GFP_KERNEL);
	if (!ref_buf) {
		pr_err("pblk: could not allocate GC buffer\n");
		goto fail_free_data;
	}
	kref_init(&ref_buf->ref);
	ref_buf->data = data;

	off = 0;
	read_left = nr_entries;
	do {
		secs_to_gc = pblk_calc_secs_to_sync(pblk, read_left, 0);
		ignored = 0;

		/* Discard invalid addresses for current GC I/O */
		for (i = 0; i < secs_to_gc; i++) {
			lba = lba_list[i + off];

			/* Omit padded entries on GC */
			if (lba == ADDR_EMPTY) {
				ignored++;
				continue;
			}

			/* If lba is mapped to a different block it is not
			 * necessary to move it to a different block.
			 *
			 * The same applies for an entry in cache; the
			 * backpointer takes care of requeuing entries
			 * mapped to a bad block. This is to avoid double GC.
			 */
			spin_lock(&pblk->trans_lock);
			gp = &pblk->trans_map[lba];
			spin_unlock(&pblk->trans_lock);

			if (nvm_addr_in_cache(gp->ppa) ||
			   (gp->rblk->parent->id != rblk->parent->id)) {
				lba_list[i + off] = ADDR_EMPTY;
				ignored++;
				continue;
			}
		}

		if (ignored == secs_to_gc)
			goto next;

		secs_in_disk = secs_to_gc - ignored;

		/* Read from GC block */
		bio_len = secs_in_disk * dev->sec_size;
		bio = bio_map_kern(q, data, bio_len, GFP_KERNEL);
		if (!bio) {
			pr_err("pblk: could not allocate GC bio\n");
			goto fail_free_krefbuf;
		}

		bio->bi_iter.bi_sector = 0; /* artificial bio */
		bio->bi_rw = READ;
		bio->bi_private = &wait;
		bio->bi_end_io = pblk_end_sync_bio;

		rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
		if (!rqd) {
			pr_err("pblk: could not allocate GC request\n");
			goto fail_free_krefbuf;
		}
		memset(rqd, 0, pblk_r_rq_size);

		ret = pblk_submit_read_list(pblk, bio, rqd, &lba_list[off],
						secs_to_gc, secs_in_disk,
						PBLK_IOTYPE_TEST);
						/* secs_to_rec, PBLK_IOTYPE_SYNC); */
		if (ret == NVM_IO_OK) {
			wait_for_completion_io(&wait);
		} else if (ret != NVM_IO_DONE) {
			pr_err("pblk: GC read request failed:%d\n", ret);
			bio_put(bio);
			goto fail_free_rqd;
		}

		pblk_free_gc_rqd(pblk, rqd);

#ifdef CONFIG_NVM_DEBUG
	atomic_add(secs_to_gc, &pblk->sync_reads);
	atomic_sub(secs_to_gc, &pblk->inflight_reads);
#endif

		bio_put(bio);
		bio_reset(bio);

		/* Write to buffer */
		bio = bio_map_kern(q, data, bio_len, GFP_KERNEL);
		if (!bio) {
			pr_err("pblk: could not allocate GC bio\n");
			goto fail_free_krefbuf;
		}

		bio->bi_iter.bi_sector = 0; /* artificial bio */
		bio->bi_rw = WRITE;
write_retry:
		/* Writes to the buffer fail due to lack of space */
		if (!pblk_write_list_to_cache(pblk, bio, PBLK_IOTYPE_REF,
					&lba_list[off], ref_buf, secs_to_gc,
					secs_in_disk, &ret)) {
			schedule();
			goto write_retry;
		}

		bio_endio(bio);

next:
		read_left -= secs_to_gc;
		off += secs_to_gc;
		moved += secs_to_gc;

		/* Use count as a heuristic for setting up a job in workqueue */
		if (pblk_rb_count(&pblk->rwb) >= pblk->min_write_pgs)
			pblk_write_kick(pblk);
	} while (read_left > 0);

	kref_put(&ref_buf->ref, pblk_free_ref_mem);

	return moved;

fail_free_rqd:
	pblk_free_gc_rqd(pblk, rqd);
fail_free_krefbuf:
	kfree(ref_buf);
fail_free_data:
	kfree(data);
out:
	return moved;
}

