/*
 * Copyright: Matias Bjorling <mb@bjorling.me>
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
 */

#ifndef GENNVM_H_
#define GENNVM_H_

#include <linux/module.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>

struct gen_bmi_blk {
	struct list_head list;
	struct ppa_addr ppa;
	unsigned long seqnr;
	unsigned long erase_cnt;
	unsigned int version;
};

struct gen_lun {
	struct nvm_lun vlun;

	int reserved_blocks;
	/* lun block lists */
	struct list_head used_list;	/* In-use blocks */
	struct list_head free_list;	/* Not used blocks i.e. released
					 * and ready for use
					 */
	struct list_head bb_list;	/* Bad blocks. Mutually exclusive with
					 * free_list and used_list
					 */
};

enum {
	GENNVM_ST_UNINITIALIZED	= 0,
	GENNVM_ST_INITIALIZED	= 1,
	GENNVM_ST_PROBED	= 2,
	GENNVM_ST_RUNNING	= 3,
};

struct gen_nvm {
	struct nvm_dev *dev;

	int nr_luns;
	struct gen_lun *luns;
	struct list_head area_list;

	struct list_head bmi_blk_list;	/* List of physical data blocks with
					 * BMI data
					 */

	int state; /* GENNVN_ST_* */
};

struct gennvm_area {
	struct list_head list;
	sector_t begin;
	sector_t end;	/* end is excluded */
};

#define gennvm_for_each_lun(bm, lun, i) \
	for ((i) = 0, lun = &(bm)->luns[0]; \
		(i) < (bm)->nr_luns; (i)++, lun = &(bm)->luns[(i)])

#define gennvm_for_each_lun_ppa(dev, ppa, chid, lunid) \
	for ((chid) = 0, (ppa).ppa = 0; (chid) < (dev)->nr_chnls; (chid)++, (ppa).g.ch = (chid)) \
		for ((lunid) = 0; (lunid) < (dev)->luns_per_chnl; (lunid)++, (ppa).g.lun = (lunid))



/* gennvm bmi management */
#define GENNVM_SYSBLK_MAGIC 0x474E564D /* "GNVM" */
#define GENNVM_SYSBLK_ENTRY_BIT 0x4

/* system block for disk representation */
struct gennvm_sys_block {
	__be32		magic;		/* magic signature */
	__be32		seqnr;		/* sequence number */
	__be32		erase_cnt;	/* erase count */
	__be16		version;	/* version number */
};

enum {
	NVM_REC_1B		= 0x1,
	NVM_REC_2B		= 0x2,
	NVM_REC_4B		= 0x4,
	NVM_REC_8B		= 0x8,

	NVM_REC_SNAPSHOT	= 0x10,
	NVM_REC_SNAPSHOT_CONT	= 0x11,

	NVM_REC_BMI_OPEN	= 0x20,
	NVM_REC_BMI_CLOSED	= 0x21,
	NVM_REC_END_OF_PAGE	= 0x22,
};
/* record disk representation */
struct gennvm_sys_record {
	u8		rec_type;	/* record type */
	__be64		ppa;
};

#endif /* GENNVM_H_ */
