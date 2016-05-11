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

#include <linux/list_sort.h>
#include <linux/mutex.h>

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

struct bmi_blk {
	struct list_head list;
	struct ppa_addr ppa;
	unsigned long seqnr;
	unsigned long erase_cnt;
	unsigned int version;
};

#define BMI_SYSBLK_MAGIC 0x474E564D /* "GNVM" */
#define BMI_MAX_REC_SIZE 32 /* triggers buffer write when less than max record
			       size available */

/* system block for disk representation */
struct bmi_sys_blk {
	__be32		magic;		/* magic signature */
	__be32		seqnr;		/* sequence number */
	__be32		erase_cnt;	/* erase count */
	__be16		version;	/* version number */
};

enum {
	BMI_REC_1B		= 0x1,
	BMI_REC_2B		= 0x2,
	BMI_REC_4B		= 0x4,
	BMI_REC_8B		= 0x8,

	BMI_REC_RESERVE_BLK	= 0x20,
	BMI_REC_RELEASE_BLK	= 0x21,
	BMI_REC_END_OF_PAGE	= 0x22,
};

struct rec_resv_blk {
	char rec_type;
	__le64 ppa;
	__le64 owner;
} __attribute__ ((__packed__));

struct rec_rele_blk {
	char rec_type;
	__le64 ppa;
} __attribute__ ((__packed__));

static void bmi_rp_resv_blk(struct gen_nvm *gn, struct rec_resv_blk *oblk)
{
	struct nvm_block *nblk;
	struct gen_lun *nlun;
	struct ppa_addr ppa;
	unsigned long long owner;

	ppa.ppa = le64_to_cpu(oblk->ppa);
	owner = le64_to_cpu(oblk->owner);

	nlun = gennvm_get_lun_from_ppa(gn, ppa);
	nblk = &nlun->vlun.blocks[ppa.g.blk];

	nblk->state = NVM_BLK_ST_OPEN;
	list_move_tail(&nblk->list, &nlun->used_list);
	nlun->vlun.nr_free_blocks--;
	nlun->vlun.nr_open_blocks++;

	pr_err("nvm: bmi: play open blk: %u %u %u %llu\n",
				ppa.g.ch, ppa.g.lun, ppa.g.blk, owner);
}

static void bmi_rp_rele_blk(struct gen_nvm *gn, struct rec_rele_blk *oblk)
{
	struct nvm_block *nblk;
	struct gen_lun *nlun;
	struct ppa_addr ppa;

	ppa.ppa = le64_to_cpu(oblk->ppa);

	nlun = gennvm_get_lun_from_ppa(gn, ppa);
	nblk = &nlun->vlun.blocks[ppa.g.blk];

	list_move_tail(&nblk->list, &nlun->free_list);
	nlun->vlun.nr_closed_blocks--;
	nlun->vlun.nr_free_blocks++;
	nblk->state = NVM_BLK_ST_FREE;

	pr_err("nvm: bmi: play close blk: %u %u %u\n",
				ppa.g.ch, ppa.g.lun, ppa.g.blk);
}

static int bmi_rp_fpg(struct gen_nvm *gn, char *data, int size)
{
	char *end = data + size;
	int ret = 0;

	while (data < end) {
		int rec_type = *data;

		pr_err("nvm: bmi: play rec_type: %u\n", rec_type);

		switch (rec_type) {
		case BMI_REC_1B:
		case BMI_REC_2B:
		case BMI_REC_4B:
		case BMI_REC_8B:
			pr_err("nvm: bmi: play rec %u\n", rec_type);
			data += rec_type;
			break;
		case BMI_REC_RESERVE_BLK:
			bmi_rp_resv_blk(gn, (struct rec_resv_blk *)data);
			data += sizeof(struct rec_resv_blk);
			break;
		case BMI_REC_RELEASE_BLK:
			bmi_rp_rele_blk(gn, (struct rec_rele_blk *)data);
			data += sizeof(struct rec_rele_blk);
			break;
		case BMI_REC_END_OF_PAGE:
			pr_err("nvm: bmi: play end of page: %u\n", rec_type);
			data = end;
			break;
		default:
			pr_err("nvm: bmi: rec not supported: %u\n", rec_type);
			data = end;
			ret = -EINVAL; /* TODO: remove me when empty_page works
					  */
			break;
		}
	}

	return ret;
}

static int bmi_rp_log(struct gen_nvm *gn)
{
	struct nvm_dev *dev = gn->dev;
	struct bmi_blk *last = list_last_entry(&gn->bmi_blk_list,
							struct bmi_blk, list);
	struct bmi_blk *blk;
	int ret, i;
	void *buf;

	buf = kmalloc(dev->fpg_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/*
	 * for each bmi_blk
	 *   read page N, where n > 1 and n < nr pgs in plane block
	 *   until
	 *     read empty page or
	 *     nvm rec end of page
	 *   if valid rec_type
	 *     apply rec type to block metadata
	 */

	list_for_each_entry(blk, &gn->bmi_blk_list, list) {
		for (i = 1; i < dev->pgs_per_blk; i++) {
			struct ppa_addr ppa = blk->ppa;

			ppa.g.pg = i;

			pr_err("nvm: bmi: accessing %u %u %u %u %u\n",
					ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pg,
					ppa.g.sec);
			ret = nvm_submit_ppa_list(dev, &ppa, 1, NVM_OP_PREAD, 0,
							buf, dev->fpg_size);
			if (ret) {
				if (ret == NVM_RSP_ERR_EMPTYPAGE && blk == last)
					blk->ppa.g.pg = i;

				/* TODO: handle empty page */
				pr_err("nvm: error on read %u\n", ret); /* TODO: pr_debug */
				goto done;
			}

			/* if device doesn't support reporting EMPTY_PAGE, we
			 * end up here anyway. In that case, we rely on the
			 * bmi_replay_fpg() to return -EINVAL when no data is
			 * there. TODO: Remove when supported... */
			if (bmi_rp_fpg(gn, buf, dev->fpg_size)) {
				if (blk == last) {
					blk->ppa.g.pg = i;
					pr_err("nvm: bmi: new write goes to %u %u %u %u\n",
					ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pg);
				}
				goto done;
			}
		}
	}

done:
	kfree(buf);
	return 0;
}

static int bmi_add_blk(struct list_head *list, struct ppa_addr ppa)
{
	struct bmi_blk *blk;

	blk = kzalloc(sizeof(struct bmi_blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	blk->ppa = ppa;

	list_add_tail(&blk->list, list);

	return 0;
}

static int bmi_free_blks(struct list_head *list)
{
	struct bmi_blk *blk, *tmp;

	list_for_each_entry_safe(blk, tmp, list, list) {
		list_del(&blk->list);
		kfree(blk);
	}

	return 0;
}

static int bmi_get_blks(struct gen_nvm *gn, int blk_type, int max,
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

			ret = bmi_add_blk(bmi_blk_list, ppa);
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
	bmi_free_blks(bmi_blk_list);
	kfree(blks);
	return ret;
}

static int bmi_mark_blk(struct gen_nvm *gn, struct ppa_addr *ppas,
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
		pr_err("nvm: bmi: failed bb mark\n");
		return -EINVAL;
	}

	return ret;
}

static int bmi_get_next_seqnr(struct gen_nvm *gn)
{
	int next_seq_nr;

	spin_lock(&gn->bmi_lock);
	next_seq_nr = ++(gn->bmi_latest_seqnr);
	spin_unlock(&gn->bmi_lock);

	return next_seq_nr;
}

static struct ppa_addr *bmi_create_ppalist(struct gen_nvm *gn,
							struct ppa_addr ppa)
{
	struct nvm_dev *dev = gn->dev;
	struct ppa_addr *ppalist;
	int i;

	ppalist = kzalloc(dev->sec_per_pg, GFP_KERNEL);
	if (!ppalist)
		return ERR_PTR(-ENOMEM);

	/* prepare ppa list */
	for (i = 0; i < dev->sec_per_pg; i++) {
		ppalist[i] = ppa;
		ppa.g.sec++;
	}

	return ppalist;
}

static void bmi_free_ppalist(void *ppalist)
{
	kfree(ppalist);
}

static int bmi_prepare_blk(struct gen_nvm *gn, struct bmi_blk *b)
{
	struct nvm_dev *dev = gn->dev;
	struct bmi_sys_blk sysblk;
	struct ppa_addr *ppalist = NULL;
	void *data;
	int ret;

	data = kzalloc(dev->fpg_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ppalist = bmi_create_ppalist(gn, b->ppa);
	if (IS_ERR_OR_NULL(ppalist)) {
		ret = -ENOMEM;
		goto err_ppalist;
	}

	ret = nvm_erase_ppa(dev, &b->ppa, 1);
	if (ret) {
		pr_err("nvm: bmi: failed to erase bmi blk\n"); /* TODO: add paa */
		ret = -EINVAL;
		goto err_erase;
	}

	/* prepare sysblk */
	sysblk.magic = cpu_to_be32(BMI_SYSBLK_MAGIC);
	sysblk.seqnr = cpu_to_be32(bmi_get_next_seqnr(gn));
	sysblk.erase_cnt = cpu_to_be32(0);
	sysblk.version = cpu_to_be16(1);

	memcpy(data, &sysblk, sizeof(struct bmi_sys_blk));

	/* ship it */
	ret = nvm_submit_ppa(dev, ppalist, dev->sec_per_pg, NVM_OP_PWRITE, 0,
							data, dev->fpg_size);
	if (ret)
		pr_err("nvm: bmi: failed to write bmi blk\n"); /* TODO: add ppa */

	pr_err("nvm: bmi: initialized bmi blk\n");
err_erase:
	bmi_free_ppalist(ppalist);
err_ppalist:
	kfree(data);
	return ret;
}

static int bmi_init_blks(struct gen_nvm *gn)
{
	LIST_HEAD(blk_list);
	int nblks, ret = 0;

	nblks = bmi_get_blks(gn, NVM_BLK_T_MM, 0, &blk_list);
	if (nblks < 0)
		return ret;

	if (list_empty(&blk_list)) {
		struct bmi_blk *b;
		/*
		 * initialize new block by allocating a free block and mark
		 * it as an mm block.
		 */
		nblks = bmi_get_blks(gn, NVM_BLK_T_FREE, 1, &blk_list);
		if (nblks < 0)
			return ret;
		if (list_empty(&blk_list))
			return -EINVAL;
		b = list_first_entry(&blk_list, struct bmi_blk, list);

		printk("nvm: bmi: prepare single block\n");
		/* erase, write first page */
		ret = bmi_prepare_blk(gn, b);
		if (ret)
			goto err_init;

		printk("nvm: bmi: mark single block\n");
		/* mark it for later traversal */
		ret = bmi_mark_blk(gn, &b->ppa, 1, NVM_BLK_T_MM);
		if (ret)
			goto err_init;
	}

	list_splice(&blk_list, &gn->bmi_blk_list);

	return 0;
err_init:
	bmi_free_blks(&blk_list);
	return ret;
}

static int bmi_read_blk(struct nvm_dev *dev, struct bmi_blk *b)
{
	struct bmi_sys_blk sys;
	void *buf;
	int ret;

	printk("nvm: reading block %u %u %u\n", b->ppa.g.lun, b->ppa.g.blk,
			b->ppa.g.pg);
	buf = kmalloc(dev->fpg_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = nvm_submit_ppa_list(dev, &b->ppa, 1, NVM_OP_PREAD, 0,
							buf, dev->fpg_size);
	if (ret) {
		pr_err("nvm: error on read %u\n", ret); /* TODO: pr_debug */
		goto done;
	}

	memcpy(&sys, buf, sizeof(struct bmi_sys_blk));

	if (be32_to_cpu(sys.magic) == BMI_SYSBLK_MAGIC) {
		b->seqnr = be32_to_cpu(sys.seqnr);
		b->erase_cnt = be32_to_cpu(sys.erase_cnt);
		b->version = be16_to_cpu(sys.version);
		printk("nvm: b %u %u %u\n", b->seqnr, b->erase_cnt, b->version);
	} else {
		ret = 1;
	}

	printk("nvm: found data %u %x\n", ret, be32_to_cpu(sys.magic));
done:
	kfree(buf);
	return ret;
}

static int bmi_blk_seq_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct bmi_blk *ba = list_entry(a, struct bmi_blk, list);
	struct bmi_blk *bb = list_entry(b, struct bmi_blk, list);

	if (ba->seqnr > bb->seqnr)
		return 1;
	if (ba->seqnr < bb->seqnr)
		return -1;
	return 0;
}

static int bmi_read_all_blk_metadata(struct gen_nvm *gn)
{
	struct nvm_dev *dev = gn->dev;
	struct bmi_blk *blk;

	list_for_each_entry(blk, &gn->bmi_blk_list, list) {
		if (bmi_read_blk(dev, blk))
			pr_err("nvm: bmi: could not read bmi blk\n");
	}

	list_sort(NULL, &gn->bmi_blk_list, bmi_blk_seq_cmp);

	return 0;
}

static int bmi_write_buf(struct gen_nvm *gn)
{
	struct nvm_dev *dev = gn->dev;
	struct bmi_blk *cur = list_last_entry(&gn->bmi_blk_list, struct bmi_blk,
									list);
	struct ppa_addr *ppalist = NULL;
	int ret;

	ppalist = bmi_create_ppalist(gn, cur->ppa);
	if (IS_ERR_OR_NULL(ppalist))
		return -ENOMEM;

	pr_err("nvm: bmi: write buffer to ppa: %u %u %u %u\n",
				cur->ppa.g.ch, cur->ppa.g.lun, cur->ppa.g.blk,
				cur->ppa.g.pg);
	ret = nvm_submit_ppa(dev, ppalist, dev->sec_per_pg, NVM_OP_PWRITE, 0,
						gn->bmi_buf, dev->fpg_size);
	if (ret)
		pr_err("nvm: bmi: failed to write bmi blk\n"); /* TODO: add ppa */

	memset(gn->bmi_buf, 0, dev->fpg_size);
	cur->ppa.g.pg++;
	if (cur->ppa.g.pg >= dev->pgs_per_blk)
		pr_err("nvm: bmi: no more pages in blk\n");
	return 0;
}

int gennvm_bmi_reserve_blk(struct gen_nvm *gn, struct ppa_addr ppa,
						unsigned long long owner)
{
	struct rec_resv_blk *oblk =
			(struct rec_resv_blk *)&gn->bmi_buf[gn->bmi_buf_offset];
	char *eop = (char *)(oblk + 1);
	int ret;

	mutex_lock(&gn->bmi_mutex);

	/* write open record and close the buffer page to be written to media,
	 * so that the owner is recorded */
	oblk->rec_type = BMI_REC_RESERVE_BLK;
	oblk->ppa = cpu_to_le64(ppa.ppa);
	oblk->owner = cpu_to_le64(1);
	*eop = BMI_REC_END_OF_PAGE;

	ret = bmi_write_buf(gn);

	mutex_unlock(&gn->bmi_mutex);
	return ret;
}

int gennvm_bmi_release_blk(struct gen_nvm *gn, struct ppa_addr ppa)
{
	mutex_lock(&gn->bmi_mutex);

	mutex_unlock(&gn->bmi_mutex);
	return 0;
}

void gennvm_bmi_free(struct gen_nvm *gn)
{
	bmi_free_blks(&gn->bmi_blk_list);
	kfree(gn->bmi_buf);
}

int gennvm_bmi_init(struct gen_nvm *gn)
{
	struct nvm_dev *dev = gn->dev;
	int ret;
	/* Method
	 * 1. Get all blocks that are reserved for media manager
	 * 2. Read first page of all blocks, determine order blocks
	 * 3. For each block, go through updates and apply to bmi table
	 */

	spin_lock_init(&gn->bmi_lock);
	mutex_init(&gn->bmi_mutex);
	INIT_LIST_HEAD(&gn->bmi_blk_list);

	ret = bmi_init_blks(gn);
	if (ret)
		return ret;

	ret = bmi_read_all_blk_metadata(gn);
	if (ret)
		goto err_bmi;

	ret = bmi_rp_log(gn);
	if (ret)
		goto err_bmi;

	gn->bmi_buf = kzalloc(dev->fpg_size, GFP_KERNEL);
	if (!gn->bmi_buf) {
		ret = -ENOMEM;
		goto err_bmi;
	}

	return 0;
err_bmi:
	bmi_free_blks(&gn->bmi_blk_list);
	return ret;
}
