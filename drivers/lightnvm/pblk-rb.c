/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <jg@lightnvm.io>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/circ_buf.h>
#include "pblk.h"

/**
 * pblk_rb_init -- initialize ring buffer
 * @rb: ring buffer
 * @rb_entry_base: pointer to entry buffer base
 * @rb_data_base: pointer to data buffer base
 * @grace_area_sz: size of the grace area between head and tail
 * @power_size: size of ring buffer in power of two
 * @power_seg_sz: size of the segments being stored in power of two (e.g.,4KB)
 *
 * Initialize ring buffer. The data and metadata buffers must be previously
 * allocated and their size must be a power of two
 * (Documentation/circular-buffers.txt)
 */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
			void *rb_data_base, unsigned long grace_area_sz,
			unsigned int power_size, unsigned int power_seg_sz)
{
	struct pblk_rb_entry *entry;
	unsigned int i;

	rb->entries = rb_entry_base;
	rb->data = rb_data_base;
	rb->seg_size = (1 << power_seg_sz);
	rb->nr_entries = (1 << power_size);
	rb->grace_area = grace_area_sz;
	rb->mem = rb->subm = rb->sync = rb->l2p_update = 0;
	rb->sync_point = RB_EMPTY_ENTRY;

	rb->data_size = rb->nr_entries * rb->seg_size;
	if (rb->data_size & (rb->data_size - 1)) {
		pr_debug("lnvm: write buffer size forced to be power of 2\n");
		rb->data_size++;
	}

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->s_lock);
	spin_lock_init(&rb->sy_lock);
	spin_lock_init(&rb->u_lock);

	for (i = 0; i < rb->nr_entries; i++) {
		entry = &rb->entries[i];
		entry->data = rb->data + (i * rb->seg_size);
	}

#if CONFIG_NVM_DEBUG
	atomic_set(&rb->inflight_sync_point, 0);
#endif
	return 0;
}

void *pblk_rb_data_ref(struct pblk_rb *rb)
{
	return rb->data;
}

void *pblk_rb_entries_ref(struct pblk_rb *rb)
{
	return rb->entries;
}

/* Copy data to ring buffer. It handles wrap around */
static void memcpy_torb(struct pblk_rb *rb, void *buf, void *data,
								unsigned size)
{
	unsigned s1, s2;

	if (buf + size >= rb->data + rb->data_size) {
		/* Wrap around case */
		s1 = (unsigned)(rb->data + rb->data_size - buf);
		s2 = size - s1;
		memcpy(buf, data, s1);
		memcpy(rb->data, data + s1, s2);
	} else {
		memcpy(buf, data, size);
	}
}

/* Copy data from ring buffer. It handles wrap around */
static void memcpy_fromrb(struct pblk_rb *rb, void *buf, void *data,
								unsigned size)
{
	unsigned s1, s2;

	if (buf + size >= rb->data + rb->data_size) {
		/* Wrap around case */
		s1 = (unsigned)(rb->data + rb->data_size - buf);
		s2 = size - s1;
		memcpy(buf, data, s1);
		memcpy(buf + s1, rb->data, s2);
	} else {
		memcpy(buf, data, size);
	}
}

/* Copy write context metadata to buffer entry */
static void memcpy_wctx(struct pblk_w_ctx *to, struct pblk_w_ctx *from)
{
	to->bio = from->bio;
	to->lba = from->lba;
	to->flags = from->flags;
	to->ppa = from->ppa;
}

#define pblk_rb_ring_count(head, tail, size) CIRC_CNT(head, tail, size)
#define pblk_rb_ring_space(rb, head, tail, size) \
	(CIRC_SPACE(head, tail, size) - rb->grace_area)

/* Buffer space is calculated with respect to the back pointer signaling
 * synchronized entries to the media.
 */
unsigned long pblk_rb_space(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long sync = READ_ONCE(rb->sync);

	return pblk_rb_ring_space(rb, mem, sync, rb->nr_entries);
}

/* Buffer count is calculated with respect to the submission entry signaling the
 * entries that are available to send to the media
 */
unsigned long pblk_rb_count(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long subm = READ_ONCE(rb->subm);

	return pblk_rb_ring_count(mem, subm, rb->nr_entries);
}

/**
 * Returns how many entries are on the write buffer at the time of call and
 * takes the submission lock. The lock is only taken if there are any entries on
 * the buffer. This guarantees that at least the returned amount of entries
 * will be on the buffer when reading from it.
 */
unsigned long pblk_rb_count_init(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long subm = READ_ONCE(rb->subm);
	unsigned long ret;

	spin_lock(&rb->s_lock);

	ret = pblk_rb_ring_count(mem, subm, rb->nr_entries);
	if (!ret)
		spin_unlock(&rb->s_lock);
	return ret;
}

/**
 * pblk_rb_read_commit - commit submission and unlock submission path
 * @rb: ring buffer
 * @nr_entries: number of entries to be committed
 */
void pblk_rb_read_commit(struct pblk_rb *rb, unsigned int nr_entries)
{
	unsigned long subm;

	lockdep_assert_held(&rb->s_lock);

	subm = READ_ONCE(rb->subm);
	smp_store_release(&rb->subm, (subm + nr_entries) & (rb->nr_entries - 1));
	spin_unlock(&rb->s_lock);
}

/**
 * pblk_rb_read_rollback - rollback ongoing submission
 * @rb: ring buffer
 *
 * Reset submission pointer to its original position before the current
 * submission started. The effect is that the entries read from the write
 * buffer (which updates their metadata) are rolled back and will be overwritten
 * by the next write thread acquiring the submission lock. Note that submitters
 * are serialied, which guarantees that rolling back will not affect a different
 * thread.
 */
void pblk_rb_read_rollback(struct pblk_rb *rb)
{
	unsigned long subm;

	lockdep_assert_held(&rb->s_lock);

	subm = READ_ONCE(rb->subm);
	smp_store_release(&rb->subm, subm);
	spin_unlock(&rb->s_lock);
}

static void __pblk_rb_update_l2p(struct pblk_rb *rb, unsigned long *l2p_upd,
							unsigned long to_update)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct nvm_dev *dev = pblk->dev;
	struct pblk_rb_entry *entry;
	struct pblk_l2p_upd_ctx *upt_ctx;
	struct pblk_w_ctx *w_ctx;
	struct pblk_block *rblk;
	struct ppa_addr ppa;
	u64 paddr;
	unsigned long l2p_upd_l = *l2p_upd;
	unsigned long i;

	lockdep_assert_held(&rb->u_lock);

	for (i = 0; i < to_update; i++) {
		entry = &rb->entries[l2p_upd_l];

		w_ctx = &entry->w_ctx;
		upt_ctx = &w_ctx->upt_ctx;
		rblk = w_ctx->ppa.rblk;

try:
		if (pblk_lock_laddr(pblk, w_ctx->lba, 1, upt_ctx)) {
			schedule();
			goto try;
		}

		paddr = ppa_to_addr(w_ctx->ppa.ppa);
		ppa = pblk_ppa_to_gaddr(dev, global_addr(pblk, rblk, paddr));
		pblk_update_map(pblk, w_ctx->lba, rblk, ppa);

		pblk_unlock_laddr(pblk, upt_ctx, PBLK_UNLOCK_ADDR_NORM);

		l2p_upd_l = (l2p_upd_l + 1) & (rb->nr_entries - 1);
	}

	*l2p_upd = l2p_upd_l;
}

/* When we move the  l2p_update pointer, we update the l2p table - lookups will
 * point to the physical address instead of to the cacheline in the write buffer
 * from this moment on.
 */
void pblk_rb_update_l2p(struct pblk_rb *rb, unsigned int nr_entries)
{
	unsigned long count, to_update;
	unsigned long l2p_upd, mem, sync;

	spin_lock(&rb->u_lock);

	l2p_upd = smp_load_acquire(&rb->l2p_update);
	mem = smp_load_acquire(&rb->mem);
	sync = smp_load_acquire(&rb->sync);

	if (pblk_rb_ring_space(rb, mem, l2p_upd, rb->nr_entries) > nr_entries)
		goto out;

	count = pblk_rb_ring_count(sync, l2p_upd, rb->nr_entries);
	to_update = (count < nr_entries) ? count : nr_entries;

	__pblk_rb_update_l2p(rb, &l2p_upd, to_update);
	smp_store_release(&rb->l2p_update, l2p_upd);

out:
	spin_unlock(&rb->u_lock);
}

/**
 * Update the l2p entry for all sectors stored on the write buffer. This means
 * that all future lookups to the l2p table will point to a device address, not
 * to the cacheline in the write buffer.
 */
void pblk_rb_sync_l2p(struct pblk_rb *rb)
{
	unsigned long l2p_upd, sync, to_update;

	spin_lock(&rb->u_lock);

	l2p_upd = smp_load_acquire(&rb->l2p_update);
	sync = smp_load_acquire(&rb->sync);

	to_update = pblk_rb_ring_count(sync, l2p_upd, rb->nr_entries);

	__pblk_rb_update_l2p(rb, &l2p_upd, to_update);
	smp_store_release(&rb->l2p_update, l2p_upd);

	spin_unlock(&rb->u_lock);
}

/**
 * pblk_rb_write - write to ring buffer
 * @rb: ring buffer
 * @data: buffer with data to be copied. Must be at least of @nr_entries *
 * @w_ctx: write context medatada to be stored on buffer
 * rb->seg_size bytes
 * @pos: (out) base position in the buffer for the current write
 *
 * Write @nr_entries to ring buffer from @data buffer if there is enough space.
 * Typically, 4KB data chunks coming from a bio will be copied to the ring
 * buffer, thus the write will fail if not all incoming data can be copied.
 *
 * Return: 0 on success, -ENOMEM on failure
 */
int pblk_rb_write_entry(struct pblk_rb *rb, void *data, struct pblk_w_ctx w_ctx,
							unsigned int pos)
{
	struct pblk_rb_entry *entry;
	unsigned long size = rb->seg_size;
	unsigned long sync;
	unsigned int ring_pos = (pos & (rb->nr_entries - 1));
	int ret = 0;

	lockdep_assert_held(&rb->w_lock);

	sync = ACCESS_ONCE(rb->sync);

	if (pblk_rb_ring_space(rb, ring_pos, sync, rb->nr_entries) < 1) {
		ret = -ENOMEM;
		goto out;
	}

	entry = &rb->entries[ring_pos];
	memcpy_torb(rb, entry->data, data, size);
	memcpy_wctx(&entry->w_ctx, &w_ctx);

out:
	return ret;
}

unsigned long pblk_rb_write_init(struct pblk_rb *rb)
{
	/* Serialize writers */
	spin_lock(&rb->w_lock);

	return READ_ONCE(rb->mem);
}

void pblk_rb_write_commit(struct pblk_rb *rb, unsigned int nr_entries)
{
	unsigned long mem;

	lockdep_assert_held(&rb->w_lock);

	mem = READ_ONCE(rb->mem);
	smp_store_release(&rb->mem, (mem + nr_entries) & (rb->nr_entries - 1));
	spin_unlock(&rb->w_lock);
}

void pblk_rb_write_rollback(struct pblk_rb *rb)
{
	unsigned long mem;

	lockdep_assert_held(&rb->w_lock);

	mem = READ_ONCE(rb->mem);
	smp_store_release(&rb->mem, mem);
	spin_unlock(&rb->w_lock);
}

/**
 * pblk_rb_read_to_bio - read from write buffer to bio
 * @rb: ring buffer
 * @bio: write bio
 * @ctx: entry context
 * @nr_entries: number of entries to be read from the buffer
 * @sync_point: most recent sync point on this batch
 *
 * Read available entries on rb and add them to the given bio. To avoid a memory
 * copy, a page reference to the write buffer is used to be added to the bio.
 *
 * This function is used by write threads to form the write bio that will
 * persist data on the write buffer to the media.
 */
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
					struct pblk_ctx *ctx,
					unsigned int nr_entries,
					unsigned long *sync_point)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct request_queue *q = pblk->dev->q;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_rb_entry *entry;
	struct page *page;
	/* unsigned long size = nr_entries * rb->seg_size; */
	unsigned long mem, subm;
	unsigned long count;
	unsigned int pad = 0, read = 0, to_read = nr_entries;
	unsigned int i;
	int ret;

	lockdep_assert_held(&rb->s_lock);

	mem = smp_load_acquire(&rb->mem);
	subm = READ_ONCE(rb->subm);

	if ((count = pblk_rb_ring_count(mem, subm, rb->nr_entries)) < nr_entries) {
		pad = nr_entries - count;
		to_read = count;
	}

	/* entry = &rb->entries[subm]; */
	/* memcpy_fromrb(rb, buf, entry->data, size); */

	c_ctx->sentry = subm;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	/* XXX: Read one entry at a time for now */
	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[subm];

		page = vmalloc_to_page(entry->data);
		if (!page) {
			pr_err("pblk: could not allocate write bio page\n");
			goto out;
		}

		ret = bio_add_pc_page(q, bio, page, rb->seg_size, 0);
		if (ret != rb->seg_size) {
			pr_err("pblk: could not ad page to write bio\n");
			goto out;
		}

		if (entry->w_ctx.bio != NULL) {
			*sync_point = subm;
#if CONFIG_NVM_DEBUG
			atomic_dec(&rb->inflight_sync_point);
#endif
		}

		subm = (subm + 1) & (rb->nr_entries - 1);
	}

	read = to_read;

#ifdef CONFIG_NVM_DEBUG
	atomic_add(pad, &pblk->padded_writes);
#endif

out:
	return read;
}

/**
 * pblk_rb_copy_to bio - copy from write buffer to bio
 * @rb: ring buffer
 * @bio: bio to copy data to
 * @pos: position in the buffer to read from
 *
 * Read the entry pointed by @pos and copy it to the given bio.
 *
 * This function is used to copy data on the write buffer to a read bio.
 */
unsigned int pblk_rb_copy_to_bio(struct pblk_rb *rb, struct bio *bio,
								u64 pos)
{
	struct pblk_rb_entry *entry;
	struct bio_vec bv;
	struct page *page;
	void *kaddr;

	if (pos >= rb->nr_entries)
		return 0;

	entry = &rb->entries[pos];

	bv = bio_iter_iovec(bio, bio->bi_iter);
	page = bv.bv_page;
	kaddr = kmap_atomic(page);
	memcpy_fromrb(rb, kaddr + bv.bv_offset, entry->data, rb->seg_size);
	kunmap_atomic(kaddr);

	return 1;
}

struct pblk_w_ctx *pblk_rb_w_ctx(struct pblk_rb *rb, unsigned long pos)
{
	unsigned long entry = pos & (rb->nr_entries - 1);

	return &rb->entries[entry].w_ctx;
}

unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags)
{
	spin_lock_irqsave(&rb->sy_lock, *flags);

	return rb->sync;
}

unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nr_entries)
{
	unsigned long sync;

	lockdep_assert_held(&rb->sy_lock);
	sync = READ_ONCE(rb->sync);

	sync = (sync + nr_entries) & (rb->nr_entries - 1);
	smp_store_release(&rb->sync, sync);

	return sync;
}

void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long flags)
{
	lockdep_assert_held(&rb->sy_lock);

	spin_unlock_irqrestore(&rb->sy_lock, flags);
}

int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio)
{
	struct pblk_rb_entry *entry;
	unsigned long mem, subm, sync_point;
	int ret = NVM_IO_OK;

	spin_lock(&rb->s_lock);

	mem = smp_load_acquire(&rb->mem);
	sync_point = smp_load_acquire(&rb->sync_point);
	subm = READ_ONCE(rb->subm);

#if CONFIG_NVM_DEBUG
	atomic_inc(&rb->inflight_sync_point);
#endif

	if (mem == subm) {
		ret = NVM_IO_DONE;
		goto out;
	}

	sync_point = (mem == 0) ? (rb->nr_entries - 1) : (mem - 1);
	entry = &rb->entries[sync_point];

	if (entry->w_ctx.bio) {
		pr_err("pblk: Duplicated sync point:%lu\n", sync_point);
		BUG_ON(1);
		//TODO: Deal with this case
	}

	entry->w_ctx.bio = bio;
	smp_store_release(&rb->sync_point, sync_point);

out:
	spin_unlock(&rb->s_lock);
	return ret;
}

void pblk_rb_sync_point_reset(struct pblk_rb *rb, unsigned long sp)
{
	unsigned long sync_point = smp_load_acquire(&rb->sync_point);

	if (sync_point == sp)
		smp_store_release(&rb->sync_point, ADDR_EMPTY);
}

unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb)
{
	unsigned long subm, sync_point, count;

	sync_point = smp_load_acquire(&rb->sync_point);
	if (sync_point == ADDR_EMPTY)
		return 0;

	subm = READ_ONCE(rb->subm);

	/* The sync point itself counts as a sector to sync */
	count = pblk_rb_ring_count(sync_point, subm, rb->nr_entries) + 1;

	return count;
}

/*
 * Scan from the current position of the sync pointer to find the entry that
 * corresponds to the given ppa. The assumption is that the ppa is close to the
 * sync pointer thus the search will not take long.
 *
 * The caller of this function must guarantee that the sync pointer will no
 * reach the entry while it is using the metadata associated with it. With this
 * assumption in mind, there is no need to take the sync lock.
 */
struct pblk_w_ctx *pblk_rb_sync_scan_entry(struct pblk_rb *rb,
						struct ppa_addr *ppa)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct nvm_dev *dev = pblk->dev;
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	struct ppa_addr gppa;
	unsigned long sync, subm, count;
	unsigned long i;

	sync = READ_ONCE(rb->sync);
	subm = READ_ONCE(rb->subm);
	count = pblk_rb_ring_count(subm, sync, rb->nr_entries);

	for (i = 0; i < count; i++) {
		entry = &rb->entries[sync];
		w_ctx = &entry->w_ctx;

		gppa = pblk_ppa_to_gaddr(dev, global_addr(pblk,
				w_ctx->ppa.rblk, ppa_to_addr(w_ctx->ppa.ppa)));

		if (gppa.ppa == ppa->ppa)
			return w_ctx;

		sync = (sync + 1) & (rb->nr_entries - 1);
	}

	return NULL;
}

int pblk_rb_tear_down_check(struct pblk_rb *rb)
{
	int ret = 0;

	spin_lock(&rb->w_lock);
	spin_lock(&rb->s_lock);
	spin_lock(&rb->sy_lock);
	spin_lock(&rb->u_lock);

	if ((rb->mem == rb->subm) && (rb->subm == rb->sync) &&
				(rb->sync == rb->l2p_update) &&
				(rb->sync_point == RB_EMPTY_ENTRY)) {
		goto out;
	}

	if (rb->entries || rb->data)
		goto out;

	ret = 1;

out:
	spin_unlock(&rb->w_lock);
	spin_unlock(&rb->s_lock);
	spin_unlock(&rb->sy_lock);
	spin_unlock(&rb->u_lock);

	return ret;
}

#ifdef CONFIG_NVM_DEBUG
void pblk_rb_print_debug(struct pblk_rb *rb)
{
	if (rb->sync_point != ADDR_EMPTY)
		pr_info("pblk_rb: %lu\t%lu\t%lu\t%lu\t%lu\t%u\ty(%lu)\n",
			rb->nr_entries,
			rb->mem, rb->subm, rb->sync, rb->l2p_update,
			atomic_read(&rb->inflight_sync_point),
			rb->sync_point);
	else
		pr_info("pblk_rb: %lu\t%lu\t%lu\t%lu\t%lu\t%u\n",
			rb->nr_entries,
			rb->mem, rb->subm, rb->sync, rb->l2p_update,
			atomic_read(&rb->inflight_sync_point));
}
#endif

