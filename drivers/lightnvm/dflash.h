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

enum {
	NVM_PROV_SPEC_LUN = 1,
	NVM_PROV_RAND_LUN = 2,
};

struct nvm_ioctl_vblock {
	__u64 id;
	__u64 bppa;
	__u32 vlun_id;
	__u32 owner_id;
	__u32 nppas;
	__u16 ppa_bitmap;
	__u16 flags;
};

struct nvm_ioctl_io
{
	__u8 opcode;
	__u8 flags;
	__u16 nppas;
	__u32 rsvd2;
	__u64 metadata;
	__u64 addr;
	__u64 ppas;
	__u32 metadata_len;
	__u32 data_len;
	__u64 status;
	__u32 result;
	__u32 rsvd3[3];
};

/* TODO Make commands reserved in the global lightnvm ioctl opcode pool */
enum {
	/* Provisioning interface */
	NVM_BLOCK_GET_CMD = 0x40,
	NVM_BLOCK_PUT_CMD,

	/* IO Interface */
	NVM_PIO_CMD,
};

#define NVM_BLOCK_GET		_IOWR(NVM_IOCTL, NVM_BLOCK_GET_CMD, \
						struct nvm_ioctl_vblock)
#define NVM_BLOCK_PUT		_IOWR(NVM_IOCTL, NVM_BLOCK_PUT_CMD, \
						struct nvm_ioctl_vblock)
#define NVM_PIO			_IOWR(NVM_IOCTL, NVM_PIO_CMD, \
						struct nvm_ioctl_io)

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
