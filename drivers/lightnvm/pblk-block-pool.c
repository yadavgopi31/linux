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
 * pblk-block-pool.c - pblk's block provisioning
 */

#include "pblk.h"

static void blk_pool_alloc_ws(struct work_struct *work)
{
	struct pblk_blk_pool *blk_pool =
				container_of(work, struct pblk_blk_pool, ws);
	struct pblk *pblk = container_of(blk_pool, struct pblk, blk_pool);
	struct pblk_prov_queue *queue;
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	void *bitmap = blk_pool->bitmap;
	int nr_luns = blk_pool->nr_luns;
	int nr_elems;
	int bit;

provision:
	bit = -1;
	while ((bit = find_next_zero_bit(bitmap, nr_luns, bit + 1)) <
								nr_luns) {
		rlun = &pblk->luns[bit];
		queue = &blk_pool->queues[bit];

		pblk_gc_check_emergency_in(pblk, rlun);

		rblk = pblk_get_blk(pblk, rlun);
		if (!rblk) {
			pr_debug("pblk: could not get new block\n");
			continue;
		}

		spin_lock(&queue->lock);
		list_add_tail(&rblk->list, &queue->list);
		nr_elems = queue->nr_elems++;
		spin_unlock(&queue->lock);

		if (nr_elems == blk_pool->qd)
			set_bit(bit, bitmap);
	}

	if (!bitmap_full(blk_pool->bitmap, nr_luns))
		goto provision;

	mod_timer(&blk_pool->timer, jiffies + msecs_to_jiffies(10));
}

static int pblk_blk_pool_should_kick(struct pblk_blk_pool *blk_pool)
{
	/* This is just a heuristic. No need to take the lock */
	return (!bitmap_full(blk_pool->bitmap, blk_pool->nr_luns));
}

static void pblk_prov_kick(struct pblk_blk_pool *blk_pool)
{
	queue_work(blk_pool->wq, &blk_pool->ws);
}

static void blk_pool_timer_fn(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;
	struct pblk_blk_pool *blk_pool = &pblk->blk_pool;

	/* Refill pblk block pool */
	if (pblk_blk_pool_should_kick(blk_pool))
		pblk_prov_kick(blk_pool);
	else
		mod_timer(&blk_pool->timer, jiffies + msecs_to_jiffies(10));
}

struct pblk_block *pblk_blk_pool_get(struct pblk *pblk, struct pblk_lun *rlun)
{
	struct pblk_blk_pool *blk_pool = &pblk->blk_pool;
	struct pblk_block *rblk = NULL;
	struct pblk_prov_queue *queue;
	int bit = rlun->prov_pos;
	int nr_elems;

	queue = &blk_pool->queues[bit];

	spin_lock(&queue->lock);
	if (!queue->nr_elems) {
		blk_pool->qd++;
		spin_unlock(&queue->lock);
		goto out;
	}

	rblk = list_first_entry(&queue->list, struct pblk_block, list);
	nr_elems = queue->nr_elems--;
	spin_unlock(&queue->lock);

	/* TODO: Follow a richer heuristic based on flash type too */
	if (nr_elems < 2) {
		pblk_prov_kick(blk_pool);
		clear_bit(bit, blk_pool->bitmap);
	}

	spin_lock(&rlun->lock_lists);
	list_move_tail(&rblk->list, &rlun->open_list);
	spin_unlock(&rlun->lock_lists);
out:
	return rblk;
}

void pblk_blk_pool_run(struct pblk *pblk)
{
	struct pblk_blk_pool *blk_pool = &pblk->blk_pool;

	mod_timer(&blk_pool->timer, jiffies + msecs_to_jiffies(10));
}

void pblk_blk_pool_stop(struct pblk *pblk)
{
	struct pblk_blk_pool *blk_pool = &pblk->blk_pool;

	del_timer(&blk_pool->timer);
}

int pblk_blk_pool_init(struct pblk *pblk)
{
	struct pblk_blk_pool *blk_pool = &pblk->blk_pool;
	struct pblk_prov_queue *queue;
	int bitmap_len;
	int i;

	blk_pool->wq = alloc_workqueue("pblk-blk_pool",
				WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!blk_pool->wq)
		return -ENOMEM;

	/* TODO: Follow a calculation based on type of flash. Queue depth can be
	 * increased if having pressure on the write thread
	 */
	blk_pool->nr_luns = pblk->nr_luns;
	blk_pool->qd = 2;

	blk_pool->queues = kmalloc(sizeof(struct pblk_prov_queue) *
					blk_pool->nr_luns, GFP_KERNEL);
	if (!blk_pool->queues)
		goto fail_destroy_wq;

	spin_lock_init(&blk_pool->lock);

	bitmap_len = BITS_TO_LONGS(blk_pool->nr_luns) * sizeof(unsigned long);
	blk_pool->bitmap = kzalloc(bitmap_len, GFP_KERNEL);
	if (!blk_pool->bitmap)
		goto fail_free_queues;

	for (i = 0; i < blk_pool->nr_luns; i++) {
		queue = &blk_pool->queues[i];

		INIT_LIST_HEAD(&queue->list);
		spin_lock_init(&queue->lock);
		queue->nr_elems = 0;
	}

	INIT_WORK(&blk_pool->ws, blk_pool_alloc_ws);
	setup_timer(&blk_pool->timer, blk_pool_timer_fn, (unsigned long)pblk);

	return 0;

fail_free_queues:
	kfree(blk_pool->queues);
fail_destroy_wq:
	destroy_workqueue(blk_pool->wq);
	return -ENOMEM;
}

void pblk_blk_pool_free(struct pblk *pblk)
{
	struct pblk_blk_pool *blk_pool = &pblk->blk_pool;
	void *bitmap = blk_pool->bitmap;
	struct pblk_block *rblk, *trblk;
	struct pblk_prov_queue *queue;
	int nr_luns = blk_pool->nr_luns;
	int i;

	/* Wait for provisioning thread to finish */
retry:
	if (!bitmap_full(bitmap, nr_luns)) {
		schedule();
		goto retry;
	}

	for (i = 0; i < nr_luns; i++) {
		queue = &blk_pool->queues[i];

		spin_lock(&queue->lock);
		list_for_each_entry_safe(rblk, trblk, &queue->list, list) {
			pblk_put_blk(pblk, rblk);
			queue->nr_elems--;
		}

		WARN_ON(queue->nr_elems);

		clear_bit(i, bitmap);
		spin_unlock(&queue->lock);
	}

	WARN_ON(!bitmap_empty(bitmap, nr_luns));

	destroy_workqueue(blk_pool->wq);
	kfree(blk_pool->queues);
	kfree(blk_pool->bitmap);
}
