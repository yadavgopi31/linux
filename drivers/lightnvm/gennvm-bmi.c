/*
 * Copyright (C) 2016 Matias Bjorling <m@bjorling.me>
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
 *
 * Implementation of the block management information for Open-Channel SSDs.
 */

#include "gennvm.h"

/* Block Management Information Layout:
 *
 * Flash Block
 * ----------------------------------------------------
 * 1st Page -> struct gennvm_sysblk
 * All other pages contain records or non-written.
 * ----------------------------------------------------
 *
 *  A flash page contains X number of records, limited by the flash page size.
 *  The records are of variable length, identified by its first byte and address
 *  of block to apply the update.
 *
 *  The rec_type is defined in gennvm.h and identifies records by either 1, 2,
 *  4, 8 bytes updates. The updates applies together with a field identifiers.
 *  I.e. each record has the following structure
 *
 *    u8 rec_type
 *    u8 field_idx;
 *    u8/u16/u32/u64 value; (NVM_REC_1B, NVM_REC_2B, NVM_REC_4B, NVM_REC_8B)
 *
 *  and additional records to facilitate snapshots (NVM_REC_SNAPSHOT) and pages
 *  that have been closed (NVM_REC_END_OF_PAGE) prematurely because of a
 *  reserve/release block update.
 *
 *  When iterating flash page, an empty (unwritten) flash page is detected by
 *  reading and fails with NVM_RSP_ERR_EMPTYPAGE error code.
 *
 * Data requirement:
 *
 *  Flash pages may only be written in e.g. 16K granularity. A 1TB device, with
 *  64K blocks and possibility to be erased 10K times requires 64K*10K updates.
 *  To serve this, the total block usage is 256 blocks with 256 pages for the
 *  lifetime of the device. Approximately 0.3% percentage of the total write
 *  capacity (total writes are 10PB). The usage can be optimized by buffering
 *  updates for values that can be approximates.
 */

static int gennvm_bmi_add_blk(struct list_head *list, struct ppa_addr ppa)
{
	struct gen_bmi_blk *bmi_blk;

	bmi_blk = kzalloc(sizeof(struct gen_bmi_blk), GFP_KERNEL);
	if (!bmi_blk)
		return -ENOMEM;

	bmi_blk->ppa = ppa;

	list_add_tail(&bmi_blk->list, list);

	return 0;
}

static int gennvm_bmi_free_blks(struct list_head *list)
{
	struct gen_bmi_blk *bmi_blk, *tmp;

	list_for_each_entry_safe(bmi_blk, tmp, list, list) {
		list_del(&bmi_blk->list);
		kfree(bmi_blk);
	}

	return 0;
}

static int gennvm_bmi_get_blks(struct gen_nvm *gn, int blk_type, int max,
						struct list_head *bmi_blk_list)
{
	struct nvm_dev *dev = gn->dev;
	int ch, lun, nr_blks;
	int ret, i, max_cnt = 0;
	struct ppa_addr ppa;
	u8 *blks;

	nr_blks = dev->blks_per_lun * dev->plane_mode;
	blks = kmalloc(nr_blks, GFP_KERNEL);
	if (!blks)
		return -ENOMEM;

	gennvm_for_each_lun_ppa(dev, ppa, ch, lun) {
		ret = nvm_get_bb_tbl(dev, ppa, blks);
		if (ret)
			goto err_blks;

		for (i = 0; i < nr_blks; i++) {
			if (blks[i] != blk_type)
				continue;

			ppa.g.pl = i % dev->plane_mode;
			ppa.g.blk = i / dev->plane_mode;

			ret = gennvm_bmi_add_blk(bmi_blk_list, ppa);
			if (ret < 0)
				goto err_blks;

			max_cnt++;
			if (max && max_cnt >= max)
				goto done;
		}
	}

done:
	kfree(blks);
	return max_cnt;
err_blks:
	gennvm_bmi_free_blks(bmi_blk_list);
	kfree(blks);
	return ret;
}

static int gennvm_bmi_mark_blk(struct gen_nvm *gn, struct ppa_addr *ppas,
							int nr_ppas, int type)
{
	struct nvm_dev *dev = gn->dev;
	struct nvm_rq rqd;
	int ret;

	memset(&rqd, 0, sizeof(struct nvm_rq));

	nvm_set_rqd_ppalist(dev, &rqd, ppas, nr_ppas, 0);
	nvm_generic_to_addr_mode(dev, &rqd);

	ret = dev->ops->set_bb_tbl(dev, &rqd.ppa_addr, rqd.nr_ppas, type);
	nvm_free_rqd_ppalist(dev, &rqd);
	if (ret) {
		pr_err("nvm: failed bb mark\n");
		return -EINVAL;
	}

	return ret;
}

static int gennvm_bmi_init_blks(struct gen_nvm *gn)
{
	LIST_HEAD(blk_list);
	int nblks, ret = 0;

	nblks = gennvm_bmi_get_blks(gn, NVM_BLK_T_MM, 0, &blk_list);
	if (nblks < 0)
		return ret;

	if (list_empty(&blk_list)) {
		struct gen_bmi_blk *b;
		/*
		 * initialize new block by allocating a free block and mark
		 * it as an mm block.
		 */
		nblks = gennvm_bmi_get_blks(gn, NVM_BLK_T_FREE, 1, &blk_list);
		if (nblks < 0)
			return ret;
		if (list_empty(&blk_list))
			return -EINVAL;
		b = list_first_entry(&blk_list, struct gen_bmi_blk, list);
		ret = gennvm_bmi_mark_blk(gn, &b->ppa, 1, NVM_BLK_T_MM);
		if (ret) {
			gennvm_bmi_free_blks(&blk_list);
			return ret;
		}
	}

	list_splice(&blk_list, &gn->bmi_blk_list);

	return 0;
}

static int gennvm_bmi_read_blk(struct nvm_dev *dev, struct gen_bmi_blk *b)
{
	int ret;
	struct gennvm_sys_block sys;
	void *buf;

	printk("nvm: reading block\n");
	buf = kmalloc(dev->fpg_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = nvm_submit_ppa_list(dev, &b->ppa, 1, NVM_OP_PREAD, 0,
							buf, dev->fpg_size);
	if (!ret) {
		memcpy(&sys, buf, sizeof(struct gennvm_sys_block));

		if (be32_to_cpu(sys.magic) != GENNVM_SYSBLK_MAGIC)
			ret = -EINVAL;

		b->seqnr = be32_to_cpu(sys.seqnr);
		b->erase_cnt = be32_to_cpu(sys.erase_cnt);
		b->version = be32_to_cpu(sys.version);

		if (be32_to_cpu(sys.magic) != GENNVM_SYSBLK_MAGIC)
			ret = -1;

		printk("nvm: found data %u %x\n", ret, be32_to_cpu(sys.magic));
	}

	printk("nvm: b %u %u %u\n", b->seqnr, b->erase_cnt, b->version);
	kfree(buf);

	return ret;
}

static int gennvm_bmi_read_all_blk_metadata(struct gen_nvm *gn)
{
	struct nvm_dev *dev = gn->dev;
	struct gen_lun *lun;
	struct gen_bmi_blk *bmi_blk;
	int i;

	for (i = 0; i < gn->nr_luns; i++) {
		lun = &gn->luns[i];

		printk("nvm: lun: %u\n", i);
		list_for_each_entry(bmi_blk, &gn->bmi_blk_list, list) {
			if (gennvm_bmi_read_blk(dev, bmi_blk))
				pr_err("could not read bmi blk\n");
		}
	}

	return 0;
}

void gennvm_bmi_free(struct gen_nvm *gn)
{
	gennvm_bmi_free_blks(&gn->bmi_blk_list);
}

int gennvm_bmi_init(struct gen_nvm *gn)
{
	int ret;
	/* Method
	 * 1. Get all blocks that are reserved for media manager
	 * 2. Read first page of all blocks, determine order blocks
	 * 3. For each block, go through updates and apply to bmi table
	 */

	ret = gennvm_bmi_init_blks(gn);
	if (ret)
		return ret;

	ret = gennvm_bmi_read_all_blk_metadata(gn);
	if (ret)
		return ret;

	return 0;
}
