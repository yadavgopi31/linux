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
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 * TODO: Expose through sysfs for:
 *   - Select number of writable luns
 *   - Choose strategy:
 *     - Stripe across writable luns
 *     - Write to one block (one lun) at a time
 *   - Configure mapping parameters for relevant strategies (sysfs)
 */

#include "pblk.h"

static int pblk_map_next_lun(struct pblk *pblk)
{
	int lun_pos;

	spin_lock(&pblk->w_luns.lock);
	lun_pos = ++pblk->w_luns.next_w_lun;
	if (pblk->w_luns.next_w_lun == pblk->w_luns.nr_luns)
		lun_pos = pblk->w_luns.next_w_lun = 0;
	spin_unlock(&pblk->w_luns.lock);

	return lun_pos;
}

int pblk_map_replace_lun(struct pblk *pblk)
{
	int next_lun;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&pblk->w_luns.lock);

	if (pblk->w_luns.nr_luns == pblk->nr_luns)
		pr_err("pblk: corrupt mapping\n");
#endif

	next_lun = ++pblk->w_luns.next_lun;
	if (pblk->w_luns.next_lun == pblk->nr_luns)
		next_lun = pblk->w_luns.next_lun = 0;

	return next_lun;
}

static struct pblk_lun *get_map_next_lun(struct pblk *pblk, int *lun_pos)
{
	*lun_pos = pblk_map_next_lun(pblk);

	return pblk->w_luns.luns[*lun_pos];
}

static struct pblk_lun *pblk_map_get_lun_rr(struct pblk *pblk, int *lun_pos,
					    int is_gc)
{
	unsigned int i;
	struct pblk_lun *rlun, *max_free;

	if (!is_gc)
		return get_map_next_lun(pblk, lun_pos);

	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns.
	 */
	max_free = &pblk->luns[0];
	*lun_pos = 0;

	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate.
	 */
	for (i = 0; i < pblk->w_luns.nr_luns; i++) {
		rlun = pblk->w_luns.luns[i];

		if (rlun->parent->nr_free_blocks >
					max_free->parent->nr_free_blocks) {
			max_free = rlun;
			*lun_pos = i;
		}
	}

	return max_free;
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk. Mapping occurs at a page granurality, i.e., if a
 * page is 4 sectors, then each map entails 4 lba-ppa mappings - @nr_secs is the
 * number of sectors in the page, taking number of planes also into
 * consideration
 *
 * TODO: We are missing GC path
 * TODO: Add support for MLC and TLC padding. For now only supporting SLC
 */
int pblk_map_rr_page(struct pblk *pblk, unsigned int sentry,
		     struct ppa_addr *ppa_list,
		     struct pblk_sec_meta *meta_list,
		     unsigned int nr_secs, unsigned int valid_secs)
{
	struct pblk_block *rblk;
	struct pblk_lun *rlun;
	int lun_pos;
	int gen_emergency_gc;
	int ret = 0;

try_lun:
	gen_emergency_gc = pblk_gc_is_emergency(pblk);
	rlun = pblk_map_get_lun_rr(pblk, &lun_pos, gen_emergency_gc);
	spin_lock(&rlun->lock);

try_cur:
	rblk = rlun->cur;

	/* Account for grown bad blocks */
	if (unlikely(block_is_bad(rblk))) {
		if (!pblk_replace_blk(pblk, rblk, rlun, -1)) {
			spin_unlock(&rlun->lock);
			goto try_lun;
		}
		goto try_cur;
	}

	ret = pblk_map_page(pblk, rblk, sentry, ppa_list, meta_list,
							nr_secs, valid_secs);
	if (ret) {
		if (!pblk_replace_blk(pblk, rblk, rlun, lun_pos)) {
			spin_unlock(&rlun->lock);
			goto try_lun;
		}
		goto try_cur;
	}

	spin_unlock(&rlun->lock);
	return ret;
}

int pblk_map_init(struct pblk *pblk)
{
	int i;

	/* TODO: This should come from sysfs and be configurable */
	pblk->w_luns.nr_luns = pblk->nr_luns;
	pblk->w_luns.next_lun = -1;
	pblk->w_luns.next_w_lun = -1;

	pblk->w_luns.luns = kcalloc(pblk->w_luns.nr_luns, sizeof(void *),
								GFP_KERNEL);
	if (!pblk->luns)
		return -ENOMEM;

	spin_lock_init(&pblk->w_luns.lock);

	/* Set write luns in order to start with */
	for (i = 0; i < pblk->w_luns.nr_luns; i++)
		pblk->w_luns.luns[i] = &pblk->luns[i];

	return 0;
}

void pblk_map_free(struct pblk *pblk)
{
	kfree(pblk->w_luns.luns);
}
