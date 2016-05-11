/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.h)
 * Initial release: Matias Bjorling <m@bjorling.me>
 * Write buffering: Javier Gonzalez <jg@lightnvm.io>
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
 * Implementation of a Physical Block-device target for Open-channel SSDs.
 *
 * Derived from rrpc.h
 */

#ifndef PBLK_H_
#define PBLK_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/crc32.h>

#include <linux/lightnvm.h>

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10
#define GC_TIME_SECS 100

#define PBLK_SECTOR (512)
#define PBLK_EXPOSED_PAGE_SIZE (4096)

#define NR_PHY_IN_LOG (PBLK_EXPOSED_PAGE_SIZE / PBLK_SECTOR)

/* Sync strategies from write buffer to media */
enum {
	NVM_SYNC_SOFT	= 0x0,		/* Only submit at max_write_pgs
					 * supported by the device, typically 64
					 * pages (256k). This option ignores
					 * sync I/Os from the upper layers
					 * (e.g., REQ_FLUSH, REQ_FUA).
					 */
	NVM_SYNC_HARD	= 0x1,		/* Submit the whole buffer. Add padding
					 * if necessary to respect the device's
					 * min_write_pgs. Respect sync I/Os.
					 */
	NVM_SYNC_OPORT	= 0x2,		/* Submit what we can, always respecting
					 * the device's min_write_pgs and sync
					 * I/Os.
					 */
};

struct pblk_sec_meta {
	u64 lba;
	u64 reserved;
};

struct pblk_locked_list {
	struct list_head lock_list;
	spinlock_t lock;
};

struct pblk_l2p_upd_ctx {
	struct list_head list;
	sector_t l_start;
	sector_t l_end;
};

/* Logical to physical mapping */
struct pblk_addr {
	struct ppa_addr ppa;		/* cacheline OR physical address */
	struct pblk_block *rblk;	/* reference to pblk block for lookup */
};

/* Completion context */
struct pblk_compl_ctx {
	unsigned int sentry;
	unsigned int nr_valid;
	unsigned int nr_padded;
};

struct pblk_compl_close_ctx {
	struct pblk_block *rblk;	/* reference to pblk block for lookup */
};

struct pblk_ctx {
	struct list_head list;		/* Head for out-of-order completion */
	void *c_ctx;			/* Completion context */
	int flags;			/* Context flags */
};

/* Read context */
struct pblk_r_ctx {
	struct pblk_l2p_upd_ctx upt_ctx;/* Update context for l2p table */
	int flags;			/* Read context flags */
};

/* Write context */
struct pblk_w_ctx {
	struct bio *bio;		/* Original bio - used for completing in
					 * REQ_FUA, REQ_FLUSH case
					 */
	struct pblk_l2p_upd_ctx upt_ctx;/* Update context for l2p table */
	sector_t lba;			/* Logic addr. associated with entry */
	struct pblk_addr ppa;		/* Physic addr. associated with entry */
	int flags;			/* Write context flags */
};

/* Recovery context */
struct pblk_rec_ctx {
	struct pblk *pblk;
	struct nvm_rq *rqd;
	struct pblk_locked_list list;
	struct work_struct ws_rec;
};

struct pblk_rb_entry {
	void *data;			/* Pointer to data on this entry */
	struct pblk_w_ctx w_ctx;	/* Context for this entry */
};

#define RB_EMPTY_ENTRY (~0ULL)

struct pblk_rb {
	struct pblk_rb_entry *entries;	/* Ring buffer entries */
	unsigned long mem;		/* Write offset - points to next
					 * writable entry in memory
					 */
	unsigned long subm;		/* Read offset - points to last entry
					 * that has been submitted to the media
					 * to be persisted
					 */
	unsigned long sync;		/* Synced - backpointer that signals
					 * the last submitted entry that has
					 * been successfully persisted to media
					 */
	unsigned long sync_point;	/* Sync point - last entry that must be
					 * flushed to the media. Used with
					 * REQ_FLUSH and REQ_FUA
					 */
	unsigned long l2p_update;	/* l2p update point - next entry for
					   which l2p mapping will be updated to
					 * contain a device ppa address (instead
					 * of a cacheline
					 */
	unsigned long nr_entries;	/* Number of entries in write buffer -
					   must be a power of two */
	unsigned long grace_area;	/* Space in buffer that must be
					 * respected between head and tail. This
					 * space is memory-specific.
					 */
	unsigned long data_size;	/* Data buffer size in bytes - must be a
					 * power of two.
					 */
	unsigned int seg_size;		/* Size of the data segments being
					 * stored on each entry. Typically this
					 * will be 4KB */

	void *data;			/* Data buffer*/

	spinlock_t w_lock;		/* Write lock */
	spinlock_t s_lock;		/* Submit lock */
	spinlock_t sy_lock;		/* Sync lock */
	spinlock_t u_lock;		/* l2p update lock */

#if CONFIG_NVM_DEBUG
	atomic_t inflight_sync_point;	/* Not served REQ_FLUSH | REQ_FUA */
#endif
};

#define PBLK_RECOVERY_SECTORS 4
/* Recovery stored in the last page of the block. A list of lbas (u64) is
 * allocated together with this structure to allow block recovery and GC.
 */
struct pblk_blk_rec_lpg {
	u32 crc;
	u32 status;
	u32 rlpg_len;
	u32 req_len;
};

struct pblk_block {
	struct nvm_block *parent;
	struct pblk_lun *rlun;
	struct list_head prio;
	struct list_head list;

	struct pblk_blk_rec_lpg *rlpg;

	unsigned long *sync_bitmap;	/* Bitmap representing physical
					 * addresses that have been synced to
					 * the media
					 */

	/* Bitmap for invalid page entries */
	unsigned long *invalid_pages;
	/* Bitmap for free (0) / used pages (1) in the block */
	unsigned long *pages;
	/* number of pages that are invalid, wrt host page size */
	unsigned int nr_invalid_pages;

	spinlock_t lock;
};

struct pblk_lun {
	struct pblk *pblk;
	struct nvm_lun *parent;
	struct pblk_block *cur, *gc_cur;
	struct pblk_block *blocks;	/* Reference to block allocation */

	struct list_head prio_list;	/* Blocks that may be GC'ed */
	struct list_head open_list;	/* In-use open blocks. These are blocks
					 * that can be both written to and read
					 * from
					 */
	struct list_head closed_list;	/* In-use closed blocks. These are
					 * blocks that can _only_ be read from
					 */

	struct work_struct ws_gc;

	spinlock_t lock_lists;
	spinlock_t lock;
};

struct pblk {
	/* instance must be kept in top to resolve pblk in unprep */
	struct nvm_tgt_instance instance;

	struct nvm_dev *dev;
	struct gendisk *disk;

	sector_t soffset; /* logical sector offset */
	u64 poffset; /* physical page offset */
	int lun_offset;

	int nr_luns;
	struct pblk_lun *luns;

	/* calculated values */
	unsigned long long nr_secs;
	unsigned long total_blocks;

	struct pblk_rb rwb;

	int min_write_pgs; /* minimum amount of pages required by controller */
	int max_write_pgs; /* maximum amount of pages supported by controller */

	unsigned int nr_blk_dsecs; /* Number of data sectors in block */

	/* Write strategy variables. Move these into each for structure for each
	 * strategy
	 */
	atomic_t next_lun; /* Whenever a page is written, this is updated
			    * to point to the next write lun
			    */

#ifdef CONFIG_NVM_DEBUG
	/* All debug counters apply to 4kb sector I/Os */
	atomic_t inflight_writes;	/* Sectors not synced to media */
	atomic_t padded_writes;		/* Sectors padded due to flush/fua */
	atomic_t req_writes;		/* Sectors stored on write buffer */
	atomic_t sub_writes;		/* Sectors submitted from buffer */
	atomic_t sync_writes;		/* Sectors synced to media */
	atomic_t compl_writes;		/* Sectors completed in write bio */
	atomic_t inflight_reads;	/* Inflight sector read requests */
	atomic_t sync_reads;		/* Completed sector read requests */
	atomic_t recov_writes;		/* Sectors submitted from recovery */
#endif

	spinlock_t bio_lock;
	struct bio_list requeue_bios;
	struct work_struct ws_requeue;
	struct work_struct ws_writer;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device.
	 */
	struct pblk_addr *trans_map;
	struct pblk_locked_list l2p_locks;

	struct list_head compl_list;
	struct list_head recovery_list;

	mempool_t *page_pool;
	mempool_t *gcb_pool;
	mempool_t *rec_pool;
	mempool_t *r_rq_pool;
	mempool_t *w_rq_pool;

	struct timer_list gc_timer;
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;
	struct workqueue_struct *kw_wq;
};

struct pblk_block_gc {
	struct pblk *pblk;
	struct pblk_block *rblk;
	struct work_struct ws_gc;
};

/* pblk ring buffer operations */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
			void *rb_data_base, unsigned long grace_area_sz,
			unsigned int power_size, unsigned int power_seg_sz);
void *pblk_rb_data_ref(struct pblk_rb *rb);
void *pblk_rb_entries_ref(struct pblk_rb *rb);
int pblk_rb_write_entry(struct pblk_rb *rb, void *data, struct pblk_w_ctx w_ctx,
							unsigned int pos);
unsigned long pblk_rb_write_init(struct pblk_rb *rb);
void pblk_rb_write_commit(struct pblk_rb *rb, unsigned int nr_entries);
void pblk_rb_write_rollback(struct pblk_rb *rb);
void pblk_rb_update_l2p(struct pblk_rb *rb, unsigned int nr_entries);
void pblk_rb_sync_l2p(struct pblk_rb *rb);
unsigned long pblk_rb_count_init(struct pblk_rb *rb);
unsigned int pblk_rb_read(struct pblk_rb *rb, void *buf,
					struct pblk_ctx *ctx,
					unsigned int nr_entries);
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
					struct pblk_ctx *ctx,
					unsigned int nr_entries,
					unsigned long *sp);
void pblk_rb_read_commit(struct pblk_rb *rb, unsigned int entries);
void pblk_rb_read_rollback(struct pblk_rb *rb);
unsigned int pblk_rb_copy_to_bio(struct pblk_rb *rb, struct bio *bio,
								u64 pos);
struct pblk_w_ctx *pblk_rb_w_ctx(struct pblk_rb *rb, unsigned long pos);
unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags);
unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nr_entries);
void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long flags);
int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio);
unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb);
void pblk_rb_sync_point_reset(struct pblk_rb *rb, unsigned long sp);
struct pblk_w_ctx *pblk_rb_sync_scan_entry(struct pblk_rb *rb,
						struct ppa_addr *ppa);
unsigned long pblk_rb_space(struct pblk_rb *rb);
unsigned long pblk_rb_count(struct pblk_rb *rb);
int pblk_rb_tear_down_check(struct pblk_rb *rb);

#ifdef CONFIG_NVM_DEBUG
void pblk_rb_print_debug(struct pblk_rb *rb);
#endif

static inline void *pblk_rlpg_to_llba(struct pblk_blk_rec_lpg *lpg)
{
	return lpg + 1;
}

static inline struct pblk_ctx *pblk_set_ctx(struct pblk *pblk,
							struct nvm_rq *rqd)
{
	struct pblk_ctx *c;

	c = nvm_rq_to_pdu(rqd);
	c->c_ctx = (void*)(c + 1);

	return c;
}

static inline void pblk_memcpy_addr(struct pblk_addr *to,
							struct pblk_addr *from)
{
	to->ppa = from->ppa;
	to->rblk = from->rblk;
}

/* Calculate the page offset of within a block from a generic address */
static inline u64 pblk_gaddr_to_pg_offset(struct nvm_dev *dev,
							struct ppa_addr p)
{
	/* FIXME: The calculation is correct, but the variable naming is
	 * misleading. Change this.
	 */
	return (u64) (p.g.pg * dev->sec_per_pl) +
				(p.g.pl * dev->sec_per_pg) + p.g.sec;
}

static inline struct ppa_addr pblk_cacheline_to_ppa(u64 addr)
{
	struct ppa_addr gp;

	gp.c.line = (u64)addr;
	gp.c.is_cached = 1;

	return gp;
}

/* Calculate global addr for the given block */
static u64 block_to_addr(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_block *blk = rblk->parent;

	return blk->id * pblk->dev->sec_per_blk;
}

static u64 global_addr(struct pblk *pblk, struct pblk_block *rblk, u64 paddr)
{
	return block_to_addr(pblk, rblk) + paddr;
}

static inline struct ppa_addr pblk_dev_addr_to_ppa(u64 addr)
{
	struct ppa_addr gp;

	gp.ppa = (u64)addr;
	gp.c.is_cached = 0;

	return gp;
}

static struct ppa_addr linear_to_generic_addr(struct nvm_dev *dev,
							struct ppa_addr r)
{
	struct ppa_addr l;
	int secs, pgs, pls, blks, luns;
	sector_t ppa = r.ppa;

	l.ppa = 0;

	div_u64_rem(ppa, dev->sec_per_pg, &secs);
	l.g.sec = secs;

	sector_div(ppa, dev->sec_per_pg);
	div_u64_rem(ppa, dev->nr_planes, &pls);
	l.g.pl = pls;

	sector_div(ppa, dev->nr_planes);
	div_u64_rem(ppa, dev->pgs_per_blk, &pgs);
	l.g.pg = pgs;

	sector_div(ppa, dev->pgs_per_blk);
	div_u64_rem(ppa, dev->blks_per_lun, &blks);
	l.g.blk = blks;

	sector_div(ppa, dev->blks_per_lun);
	div_u64_rem(ppa, dev->luns_per_chnl, &luns);
	l.g.lun = luns;

	sector_div(ppa, dev->luns_per_chnl);
	l.g.ch = ppa;

	return l;
}

static struct ppa_addr pblk_ppa_to_gaddr(struct nvm_dev *dev, u64 addr)
{
	struct ppa_addr paddr;

	paddr.ppa = addr;
	return linear_to_generic_addr(dev, paddr);
}

static void pblk_page_invalidate(struct pblk *pblk, struct pblk_addr *a)
{
	struct pblk_block *rblk = a->rblk;
	u64 block_ppa;

	BUG_ON(nvm_addr_in_cache(a->ppa));

	if (a->ppa.ppa == ADDR_EMPTY) {
		BUG_ON(a->rblk);
		return;
	}

	block_ppa = pblk_gaddr_to_pg_offset(pblk->dev, a->ppa);
	WARN_ON(test_and_set_bit(block_ppa, rblk->invalid_pages));
	rblk->nr_invalid_pages++;
}

static inline void pblk_update_map(struct pblk *pblk, sector_t laddr,
				struct pblk_block *rblk, struct ppa_addr ppa)
{
	struct pblk_addr *gp;

	BUG_ON(laddr >= pblk->nr_secs);

	gp = &pblk->trans_map[laddr];
	if (gp->rblk)
		pblk_page_invalidate(pblk, gp);

	gp->ppa = ppa;
	gp->rblk = rblk;
}

static inline struct pblk_block *pblk_get_rblk(struct pblk_lun *rlun,
								int blk_id)
{
	struct pblk *pblk = rlun->pblk;
	int lun_blk = blk_id % pblk->dev->blks_per_lun;

	return &rlun->blocks[lun_blk];
}

static inline sector_t pblk_get_laddr(struct bio *bio)
{
	return bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
}

static inline unsigned int pblk_get_pages(struct bio *bio)
{
	return  bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;
}

static inline sector_t pblk_get_sector(sector_t laddr)
{
	return laddr * NR_PHY_IN_LOG;
}

static inline int request_intersects(struct pblk_l2p_upd_ctx *r,
				sector_t laddr_start, sector_t laddr_end)
{
	return (laddr_end >= r->l_start) && (laddr_start <= r->l_end);
}

static int __pblk_lock_laddr(struct pblk *pblk, sector_t laddr,
				unsigned pages, struct pblk_l2p_upd_ctx *r)
{
	sector_t laddr_end = laddr + pages - 1;
	struct pblk_l2p_upd_ctx *rtmp;

	spin_lock_irq(&pblk->l2p_locks.lock);
	list_for_each_entry(rtmp, &pblk->l2p_locks.lock_list, list) {
		if (unlikely(request_intersects(rtmp, laddr, laddr_end))) {
			/* existing, overlapping request, come back later */
			spin_unlock_irq(&pblk->l2p_locks.lock);
			return 1;
		}
	}

	r->l_start = laddr;
	r->l_end = laddr_end;

	list_add_tail(&r->list, &pblk->l2p_locks.lock_list);
	spin_unlock_irq(&pblk->l2p_locks.lock);
	return 0;
}

static inline int pblk_lock_laddr(struct pblk *pblk, sector_t laddr,
				unsigned pages, struct pblk_l2p_upd_ctx *r)
{
	BUG_ON((laddr + pages) > pblk->nr_secs);

	return __pblk_lock_laddr(pblk, laddr, pages, r);
}

static inline int pblk_lock_rq(struct pblk *pblk, struct bio *bio,
					struct pblk_l2p_upd_ctx *l2p_ctx)
{
	sector_t laddr = pblk_get_laddr(bio);
	unsigned int pages = pblk_get_pages(bio);

	return pblk_lock_laddr(pblk, laddr, pages, l2p_ctx);
}

#define PBLK_UNLOCK_ADDR_INT 0
#define PBLK_UNLOCK_ADDR_NORM 1

static inline void pblk_unlock_laddr(struct pblk *pblk,
				struct pblk_l2p_upd_ctx *r, int int_flags)
{
	if (int_flags == PBLK_UNLOCK_ADDR_INT) {
		unsigned long flags;

		spin_lock_irqsave(&pblk->l2p_locks.lock, flags);
		list_del_init(&r->list);
		spin_unlock_irqrestore(&pblk->l2p_locks.lock, flags);
	} else {
		spin_lock_irq(&pblk->l2p_locks.lock);
		list_del_init(&r->list);
		spin_unlock_irq(&pblk->l2p_locks.lock);
	}
}

static inline void pblk_unlock_rq(struct pblk *pblk, struct bio *bio,
				struct pblk_l2p_upd_ctx *l2p_ctx, int int_flags)
{
	unsigned int nr_secs = pblk_get_pages(bio);

	BUG_ON((l2p_ctx->l_start + nr_secs) > pblk->nr_secs);

	pblk_unlock_laddr(pblk, l2p_ctx, int_flags);
}

#endif /* PBLK_H_ */
