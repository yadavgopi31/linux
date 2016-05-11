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

	int state; /* GENNVN_ST_* */

	/* gennvm-bmi.c */
	spinlock_t bmi_lock;
	struct mutex bmi_mutex;
	int bmi_latest_seqnr;
	struct list_head bmi_blk_list;	/* List of physical data blocks with
					 * BMI data
					 */
	char *bmi_buf;
	int bmi_buf_offset;
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

static inline struct gen_lun *gennvm_get_lun_from_ppa(struct gen_nvm *gn,
							struct ppa_addr ppa)
{
	struct nvm_dev *dev = gn->dev;

	return &gn->luns[(dev->luns_per_chnl * ppa.g.ch) + ppa.g.lun];
}

/* gennvm-bmi.c */
extern int gennvm_bmi_reserve_blk(struct gen_nvm *, struct ppa_addr,
							unsigned long long);
extern int gennvm_bmi_release_blk(struct gen_nvm *, struct ppa_addr);

extern int gennvm_bmi_init(struct gen_nvm *);
extern void gennvm_bmi_free(struct gen_nvm *);

#endif /* GENNVM_H_ */
