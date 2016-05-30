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
 * Implementation of a physical block-device target for Open-channel SSDs.
 */

#ifndef PBLK_GC_H

#define PBLK_GC_TRIES 3

int pblk_gc_move_valid_pages(struct pblk *pblk, struct pblk_block *rblk,
			     u64 *lba_list, unsigned int nr_entries);
#endif

