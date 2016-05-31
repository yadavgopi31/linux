/*
 * Copyright (C) 2016 CNEX Labs
 * Initial: Javier Gonzalez <jg@lightnvm.io>
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
 * Recovery for pblk: physical block-device target
 */

#ifndef PBLK_RECOVERY_H
#define PBLK_RECOVERY_H

void pblk_run_recovery(struct pblk *pblk, struct pblk_block *rblk);
int pblk_recov_setup_end_rq(struct pblk *pblk, struct pblk_ctx *ctx,
			  struct pblk_rec_ctx *recovery, u64 *comp_bits,
			  unsigned int c_entries);
int pblk_recov_read(struct pblk *pblk, struct pblk_block *rblk,
		    void *recov_page, unsigned int page_size);
u64 *pblk_recov_get_lba_list(struct pblk *pblk, void *recov_page);
int pblk_recov_scan_blk(struct pblk *pblk, struct pblk_block *rblk);
void pblk_recov_clean_bb_list(struct pblk *pblk, struct pblk_lun *rlun);
void pblk_close_rblk_queue(struct work_struct *work);

#endif
