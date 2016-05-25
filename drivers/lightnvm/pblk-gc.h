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


#ifndef PBLK_GC_H

#define PBLK_GC_TRIES 3

int pblk_gc_init(struct pblk *pblk);
void pblk_gc_exit(struct pblk *pblk);
void pblk_gc_queue(struct work_struct *work);
void pblk_lun_gc(struct work_struct *work);
int pblk_gc_move_valid_secs(struct pblk *pblk, struct pblk_block *rblk,
			     u64 *lba_list, unsigned int nr_entries);

static inline int pblk_gc_invalidate_sec(struct pblk_block *rblk,
					 struct ppa_addr a)
{
	rblk->nr_invalid_secs++;
	return test_and_set_bit(a.ppa, rblk->invalid_bitmap);
}

#endif

