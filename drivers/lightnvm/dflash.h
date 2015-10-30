/*
 * Copyright (C) 2015 CNEX Labs. All rights reserved.
 * Initial release:
 *	- Javier González <javier@cnexlabs.com>
 *	- Matias Bjorling <matias@cnexlabs.com>
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
 */

#ifndef DFLASH_H_
#define DFLASH_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>
#include <uapi/linux/lightnvm.h>

#define dflash_SECTOR (512)
#define dflash_EXPOSED_PAGE_SIZE (4096)

#define NR_PHY_IN_LOG (dflash_EXPOSED_PAGE_SIZE / dflash_SECTOR)

struct dflash_lun;

struct dflash {
	struct nvm_tgt_instance instance;
	unsigned long nr_pages;
	unsigned long nr_luns;
	struct dflash_lun *luns;
	mempool_t *rq_pool;
	struct nvm_dev *dev;
	struct gendisk *disk;
};

struct dflash_lun {
	struct dflash *dflash;
	struct nvm_lun *parent;
	struct nvm_block *blocks;
	unsigned long nr_blocks;
	unsigned long nr_free_blocks;
};

static inline unsigned int dflash_get_pages(struct bio *bio)
{
	return  bio->bi_iter.bi_size / dflash_EXPOSED_PAGE_SIZE;
}

static inline sector_t dflash_get_laddr(struct bio *bio)
{
	return bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
}

static inline sector_t dflash_get_sector(sector_t laddr)
{
	return laddr * NR_PHY_IN_LOG;
}

#endif /* DFLASH_H_ */
