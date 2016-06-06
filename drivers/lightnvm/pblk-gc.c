/*
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
 * GC for pblk: physical block-device target
 */

#include "pblk.h"
#include "pblk-gc.h"
#include "pblk-recovery.h"

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
				bio_advance(bio, (*valid_secs) *
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

		(*valid_secs)++;

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

		pblk_read_ppalist_rq_list(pblk, bio, rqd, lba_list, nr_secs,
						&valid_secs, flags,
						&read_bitmap);
	} else {
		pblk_read_rq(pblk, bio, rqd, lba_list[0], flags, &read_bitmap);
	}

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
 * pblk_move_valid_secs -- migrate live data off the block
 * @pblk: the 'pblk' structure
 * @block: the block from which to migrate live sectors
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
int pblk_gc_move_valid_secs(struct pblk *pblk, struct pblk_block *rblk,
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
			goto fail_free_bio;
		}
		memset(rqd, 0, pblk_r_rq_size);

		ret = pblk_submit_read_list(pblk, bio, rqd, &lba_list[off],
						secs_to_gc, secs_in_disk,
						PBLK_IOTYPE_SYNC);
		if (ret) {
			pr_err("pblk: GC read request failed:%d\n", ret);
			bio_put(bio);
			goto fail_free_rqd;
		}

		wait_for_completion_io(&wait);
		pblk_free_gc_rqd(pblk, rqd);

		if (bio->bi_error) {
			pr_err("pblk: GC sync read failed (%u)\n",
								bio->bi_error);
			pblk_print_failed_bio(rqd, rqd->nr_ppas);
		}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(secs_to_gc, &pblk->sync_reads);
	atomic_sub(secs_to_gc, &pblk->inflight_reads);
#endif

		bio_put(bio);

		/* Write to buffer */
		bio = bio_map_kern(q, data, bio_len, GFP_KERNEL);
		if (!bio) {
			pr_err("pblk: could not allocate GC bio\n");
			goto fail_free_bio;
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

		bio_put(bio);

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
fail_free_bio:
	bio_put(bio);
fail_free_krefbuf:
	kfree(ref_buf);
fail_free_data:
	kfree(data);
out:
	return moved;
}

void pblk_gc_queue(struct work_struct *work)
{
	struct pblk_block_ws *blk_ws = container_of(work, struct pblk_block_ws,
									ws_blk);
	struct pblk *pblk = blk_ws->pblk;
	struct pblk_block *rblk = blk_ws->rblk;
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock_lists);
	list_move_tail(&rblk->list, &rlun->closed_list);
	spin_unlock(&rlun->lock_lists);

	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

	mempool_free(blk_ws, pblk->blk_ws_pool);
	pr_debug("nvm: block '%lu' is full, allow GC (sched)\n",
							rblk->parent->id);
}


/* the block with highest number of invalid pages, will be in the beginning
 * of the list
 */
static struct pblk_block *rblock_max_invalid(struct pblk_block *ra,
							struct pblk_block *rb)
{
	if (ra->nr_invalid_secs == rb->nr_invalid_secs)
		return ra;

	return (ra->nr_invalid_secs < rb->nr_invalid_secs) ? rb : ra;
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

static void pblk_block_gc(struct work_struct *work)
{
	struct pblk_block_ws *blk_ws = container_of(work, struct pblk_block_ws,
									ws_blk);
	struct pblk *pblk = blk_ws->pblk;
	struct nvm_dev *dev = pblk->dev;
	struct pblk_block *rblk = blk_ws->rblk;
	struct pblk_lun *rlun = rblk->rlun;
	void *recov_page;
	u64 *lba_list;
	u64 gc_lba_list[PBLK_MAX_REQ_ADDRS];
	unsigned int page_size = dev->sec_per_pl * dev->sec_size;
	int bit;
	int nr_ppas;
	int moved, total_moved = 0;

	mempool_free(blk_ws, pblk->blk_ws_pool);
	pr_debug("pblk: block '%lu' being reclaimed\n", rblk->parent->id);

	recov_page = kzalloc(page_size, GFP_KERNEL);
	if (!recov_page) {
		pr_err("pblk: could not allocate recovery ppa list\n");
		goto put_back;
	}

	if (pblk_recov_read(pblk, rblk, recov_page, page_size)) {
		pr_err("pblk: could not recover last page. Blk:%lu\n",
						rblk->parent->id);
		goto free_recov_page;
	}

	lba_list = pblk_recov_get_lba_list(pblk, recov_page);
	if (!lba_list) {
		pr_err("pblk: Could not interpret recover page. Blk:%lu\n",
							rblk->parent->id);
		goto free_recov_page;
	}

	bit = 0;
next_lba_list:
	nr_ppas = 0;
	do {
		bit = find_next_bit(rblk->invalid_bitmap,
						pblk->nr_blk_dsecs, bit);
		gc_lba_list[nr_ppas] = lba_list[bit];

		bit++;
		if (bit > pblk->nr_blk_dsecs)
			goto prepare_ppas;

		nr_ppas++;
	} while (nr_ppas < PBLK_MAX_REQ_ADDRS);

prepare_ppas:
	moved = pblk_gc_move_valid_secs(pblk, rblk, gc_lba_list, nr_ppas);
	if (moved != nr_ppas) {
		pr_err("pblk: could not GC all sectors:blk:%lu, GC:%d/%d/%d\n",
						rblk->parent->id,
						moved, nr_ppas,
						rblk->nr_invalid_secs);
		goto put_back;
	}

	total_moved += moved;
	if (total_moved < rblk->nr_invalid_secs)
		goto next_lba_list;

	spin_lock(&rblk->lock);
	pblk_put_blk(pblk, rblk);
	spin_unlock(&rblk->lock);

	kfree(recov_page);
	return;

free_recov_page:
	kfree(recov_page);
put_back:
	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);
}

void pblk_lun_gc(struct work_struct *work)
{
	struct pblk_lun *rlun = container_of(work, struct pblk_lun, ws_gc);
	struct pblk *pblk = rlun->pblk;
	struct nvm_lun *lun = rlun->parent;
	struct pblk_block_ws *blk_ws;
	unsigned int nr_blocks_need;

	nr_blocks_need = pblk->nr_luns *
				(pblk->dev->blks_per_lun / GC_LIMIT_INVERSE);

	if (nr_blocks_need < pblk->nr_luns)
		nr_blocks_need = pblk->nr_luns;

	spin_lock(&rlun->lock);
	while (nr_blocks_need > lun->nr_free_blocks &&
					!list_empty(&rlun->prio_list)) {
		struct pblk_block *rblk = block_prio_find_max(rlun);
		struct nvm_block *block = rblk->parent;

		if (!rblk->nr_invalid_secs)
			break;

		blk_ws = mempool_alloc(pblk->blk_ws_pool, GFP_ATOMIC);
		if (!blk_ws)
			break;

		list_del_init(&rblk->prio);

		BUG_ON(!block_is_full(pblk, rblk));

		pr_debug("pblk: selected block '%lu' for GC\n", block->id);

		blk_ws->pblk = pblk;
		blk_ws->rblk = rblk;

		INIT_WORK(&blk_ws->ws_blk, pblk_block_gc);
		queue_work(pblk->kgc_wq, &blk_ws->ws_blk);

		nr_blocks_need--;
	}
	spin_unlock(&rlun->lock);

	if (unlikely(!list_empty(&rlun->bb_list)))
		pblk_recov_clean_bb_list(pblk, rlun);

	/* TODO: Hint that request queue can be started again */
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

/*
 * timed GC every interval.
 */
static void pblk_gc_timer(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	pblk_gc_kick(pblk);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(10));
}

int pblk_gc_init(struct pblk *pblk)
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

void pblk_gc_exit(struct pblk *pblk)
{
	del_timer(&pblk->gc_timer);
	flush_workqueue(pblk->kgc_wq);

	if (pblk->krqd_wq)
		destroy_workqueue(pblk->krqd_wq);

	if (pblk->kgc_wq)
		destroy_workqueue(pblk->kgc_wq);
}



