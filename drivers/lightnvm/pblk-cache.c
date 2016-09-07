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
 * pblk-cache.c - pblk's write cache
 */

#include "pblk.h"

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
	return atomic_inc_below(&pblk->write_inflight, pblk->write_cur_speed,
								nr_secs);
}

static void pblk_may_submit_write(struct pblk *pblk, int nr_secs)
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


