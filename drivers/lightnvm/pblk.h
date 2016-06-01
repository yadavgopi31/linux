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
#define PBLK_MAX_REQ_ADDRS (64)

#define NR_PHY_IN_LOG (PBLK_EXPOSED_PAGE_SIZE / PBLK_SECTOR)

enum {
	PBLK_IOTYPE_NONE = 0,
	PBLK_IOTYPE_GC = 1,
	PBLK_IOTYPE_SYNC = 2,
	PBLK_IOTYPE_CLOSE_BLK = 4,
	PBLK_IOTYPE_PAD = 8,
	PBLK_IOTYPE_REF = 16,
};

enum {
	PBLK_BLK_ST_OPEN =	0x1,
	PBLK_BLK_ST_CLOSED =	0x2,
};

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

/* Buffer allocated after counter */
struct pblk_kref_buf {
	struct kref ref;
	void *data;
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
	int flags;			/* Read context flags */
	struct bio *orig_bio;
};

/* Recovery context */
struct pblk_rec_ctx {
	struct pblk *pblk;
	struct nvm_rq *rqd;
	struct list_head failed;
	struct work_struct ws_rec;
};

/* Write context */
struct pblk_w_ctx {
	struct bio *bio;		/* Original bio - used for completing in
					 * REQ_FUA, REQ_FLUSH case
					 */
	void *priv;			/* Private pointer */
	sector_t lba;			/* Logic addr. associated with entry */
	struct pblk_addr ppa;		/* Physic addr. associated with entry */
	int flags;			/* Write context flags */
};

struct pblk_rb_entry {
	void *data;			/* Pointer to data on this entry */
	struct pblk_w_ctx w_ctx;	/* Context for this entry */
	struct list_head index;		/* List head to enable indexes */
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
	spinlock_t r_lock;		/* Read lock */
	spinlock_t s_lock;		/* Sync lock */
	spinlock_t l2p_lock;		/* l2p update lock */

#ifdef CONFIG_NVM_DEBUG
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
	u32 nr_lbas;
	u32 nr_padded;
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

	/* Bitmap for invalid sector entries */
	unsigned long *invalid_secs;
	/* Bitmap for free (0) / used sectors (1) in the block */
	unsigned long *sectors;
	unsigned long cur_sec;
	/* number of secs that are invalid, wrt host page size */
	unsigned int nr_invalid_secs;

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
	struct list_head bb_list;	/* Grown bad blocks waiting to be
					 *disposed
					 */

	/* Counters for statistics */
	unsigned int nr_bad_blocks;	/* Number grown bad blocks */

	struct work_struct ws_gc;
	// struct work_struct ws_prov;

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
	atomic_t next_lun; /* Whenever sector is written, this is updated
			    * to point to the next write lun
			    */

#ifdef CONFIG_NVM_DEBUG
	/* All debug counters apply to 4kb sector I/Os */
	atomic_t inflight_writes;	/* Sectors not synced to media */
	atomic_t padded_writes;		/* Sectors padded due to flush/fua */
	atomic_t nr_flush;		/* Number of flush/fua I/O */
	atomic_t req_writes;		/* Sectors stored on write buffer */
	atomic_t sub_writes;		/* Sectors submitted from buffer */
	atomic_t sync_writes;		/* Sectors synced to media */
	atomic_t compl_writes;		/* Sectors completed in write bio */
	atomic_t inflight_reads;	/* Inflight sector read requests */
	atomic_t sync_reads;		/* Completed sector read requests */
	atomic_t recov_writes;		/* Sectors submitted from recovery */
	atomic_t recov_gc_writes;	/* Sectors submitted from recovery GC */
	atomic_t requeued_writes;	/* Sectors requeued in cache */
#endif

	spinlock_t bio_lock;
	spinlock_t trans_lock;
	struct bio_list requeue_bios;
	struct work_struct ws_requeue;
	struct work_struct ws_writer;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device.
	 */
	struct pblk_addr *trans_map;

	struct list_head compl_list;

	mempool_t *page_pool;
	mempool_t *blk_ws_pool;
	mempool_t *rec_pool;
	mempool_t *r_rq_pool;
	mempool_t *w_rq_pool;

	struct timer_list gc_timer;
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;
	struct workqueue_struct *kw_wq;
};

struct pblk_block_ws {
	struct pblk *pblk;
	struct pblk_block *rblk;
	struct work_struct ws_blk;
};

/*
 * pblk ring buffer operations
 */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
		 void *rb_data_base, unsigned long grace_area_sz,
			unsigned int power_size, unsigned int power_seg_sz);
void *pblk_rb_data_ref(struct pblk_rb *rb);
void *pblk_rb_entries_ref(struct pblk_rb *rb);

void pblk_rb_write_init(struct pblk_rb *rb);
unsigned long pblk_rb_write_pos(struct pblk_rb *rb);
int pblk_rb_write_entry(struct pblk_rb *rb, void *data, struct pblk_w_ctx w_ctx,
			unsigned int pos);
struct pblk_w_ctx *pblk_rb_w_ctx(struct pblk_rb *rb, unsigned long pos);
void pblk_rb_write_commit(struct pblk_rb *rb, unsigned int nr_entries);
void pblk_rb_write_rollback(struct pblk_rb *rb);

int pblk_rb_update_l2p(struct pblk_rb *rb, unsigned int nr_entries);
void pblk_rb_sync_l2p(struct pblk_rb *rb);

unsigned long pblk_rb_count_init(struct pblk_rb *rb);
unsigned int pblk_rb_read(struct pblk_rb *rb, void *buf,
			  struct pblk_ctx *ctx,
			  unsigned int nr_entries);
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
				 struct pblk_ctx *ctx,
				 unsigned int nr_entries,
				 unsigned long *sp);
unsigned int pblk_rb_read_to_bio_list(struct pblk_rb *rb, struct bio *bio,
				      struct pblk_ctx *ctx,
				      struct list_head *list,
				      unsigned int max);
unsigned int pblk_rb_copy_to_bio(struct pblk_rb *rb, struct bio *bio, u64 pos);
void pblk_rb_read_commit(struct pblk_rb *rb, unsigned int entries);
void pblk_rb_read_rollback(struct pblk_rb *rb);

unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags);
unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nr_entries);
struct pblk_rb_entry *pblk_rb_sync_scan_entry(struct pblk_rb *rb,
					      struct ppa_addr *ppa);
void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long flags);

int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio);
unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb);
void pblk_rb_sync_point_reset(struct pblk_rb *rb, unsigned long sp);

unsigned long pblk_rb_space(struct pblk_rb *rb);
unsigned long pblk_rb_count(struct pblk_rb *rb);
unsigned long pblk_rb_wrap_pos(struct pblk_rb *rb, unsigned long pos);

int pblk_rb_tear_down_check(struct pblk_rb *rb);
int pblk_rb_pos_oob(struct pblk_rb *rb, u64 pos);

/*
 * pblk shared operations
 */
int pblk_calc_secs_to_sync(struct pblk *pblk, unsigned long secs_avail,
			   unsigned long secs_to_flush);
int pblk_read_rq(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
		 sector_t laddr, unsigned long flags,
		 unsigned long *read_bitmap);
int pblk_submit_read_io(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, unsigned long flags);
int pblk_fill_partial_read_bio(struct pblk *pblk, struct bio *bio,
			       unsigned long *read_bitmap, struct nvm_rq *rqd,
			       uint8_t nr_secs);
int pblk_setup_w_multi(struct pblk *pblk, struct nvm_rq *rqd,
		       struct pblk_ctx *ctx, struct pblk_sec_meta *meta,
		       unsigned int valid_secs, int off);
int pblk_setup_w_single(struct pblk *pblk, struct nvm_rq *rqd,
			struct pblk_ctx *ctx, struct pblk_sec_meta *meta);
int pblk_alloc_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
		    struct pblk_ctx *ctx, unsigned int nr_secs);
int pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
			 struct ppa_addr ppa);
void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk);
void pblk_put_blk_unlocked(struct pblk *pblk, struct pblk_block *rblk);
void pblk_end_io(struct nvm_rq *rqd);
void pblk_end_sync_bio(struct bio *bio);

#ifdef CONFIG_NVM_DEBUG
void pblk_rb_print_debug(struct pblk_rb *rb);
#endif

static inline void pblk_write_kick(struct pblk *pblk)
{
	queue_work(pblk->kw_wq, &pblk->ws_writer);
}

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

static inline void pblk_ppa_set_empty(struct pblk_addr *ppa)
{
	ppa_set_empty(&ppa->ppa);
	ppa->rblk = NULL;
}

static inline void pblk_free_ref_mem(struct kref *ref)
{
	struct pblk_kref_buf *ref_buf;
	void *data;

	ref_buf = container_of(ref, struct pblk_kref_buf, ref);
	data = ref_buf->data;

	kfree(data);
	kfree(ref_buf);
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
	struct ppa_addr p;

	p.c.line = (u64)addr;
	p.c.is_cached = 1;

	return p;
}

/* Calculate global addr for the given block */
static u64 block_to_addr(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_block *blk = rblk->parent;

	return blk->id * pblk->dev->sec_per_blk;
}

static inline u64 global_addr(struct pblk *pblk, struct pblk_block *rblk,
			      u64 paddr)
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

static inline struct ppa_addr pblk_ppa_to_gaddr(struct nvm_dev *dev, u64 addr)
{
	struct ppa_addr paddr;

	paddr.ppa = addr;
	return linear_to_generic_addr(dev, paddr);
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
	WARN_ON(test_and_set_bit(block_ppa, rblk->invalid_secs));
	rblk->nr_invalid_secs++;
}

static inline void pblk_update_map(struct pblk *pblk, sector_t laddr,
				struct pblk_block *rblk, struct ppa_addr ppa)
{
	struct pblk_addr *gp;

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

static inline unsigned int pblk_get_secs(struct bio *bio)
{
	return  bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;
}

static inline sector_t pblk_get_sector(sector_t laddr)
{
	return laddr * NR_PHY_IN_LOG;
}

static inline int block_is_bad(struct pblk_block *rblk)
{
	return (rblk->parent->state == NVM_BLK_ST_BAD);
}

static inline int block_is_full(struct pblk *pblk, struct pblk_block *rblk)
{
#ifdef CONFIG_NVM_DEBUG
	if (!block_is_bad(rblk))
		BUG_ON(!bitmap_full(rblk->sectors, pblk->nr_blk_dsecs) &&
				rblk->cur_sec >= pblk->nr_blk_dsecs);
#endif

	return (rblk->cur_sec >= pblk->nr_blk_dsecs);
}

#endif /* PBLK_H_ */
