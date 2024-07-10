// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (c) 2016-2018 Christoph Hellwig.
 */
#include "linux/kern_levels.h"
#include "linux/ktime.h"
#include "linux/mm.h"
#include "linux/printk.h"
#include "linux/timekeeping.h"
#include <linux/module.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/backing-dev.h>
#include <linux/uio.h>
#include <linux/task_io_accounting_ops.h>
#include "trace.h"
#include <linux/filter.h>

#include "../internal.h"

/*
 * Private flags for iomap_dio, must not overlap with the public ones in
 * iomap.h:
 */
#define IOMAP_DIO_WRITE_FUA	(1 << 28)
#define IOMAP_DIO_NEED_SYNC	(1 << 29)
#define IOMAP_DIO_WRITE		(1 << 30)
#define IOMAP_DIO_DIRTY		(1 << 31)

struct iomap_dio {
	struct kiocb		*iocb;
	const struct iomap_dio_ops *dops;
	loff_t			i_size;
	loff_t			size;
	atomic_t		ref;
	unsigned		flags;
	int			error;
	bool			wait_for_completion;

	union {
		/* used during submission and for synchronous completion: */
		struct {
			struct iov_iter		*iter;
			struct task_struct	*waiter;
			struct request_queue	*last_queue;
			blk_qc_t		cookie;
		} submit;

		/* used for aio completion: */
		struct {
			struct work_struct	work;
		} aio;
	};
};

/*----zhengxd kernel stat*/
extern atomic_long_t filemap_wait_time;
extern atomic_long_t filemap_wait_count;
extern atomic_long_t iomap_hit_time;
extern atomic_long_t iomap_hit_count;
extern atomic_long_t get_page_time;
extern atomic_long_t get_page_count;
extern atomic_long_t hit_buf_time;
extern atomic_long_t hit_buf_count;
extern atomic_long_t bio_time;
extern atomic_long_t bio_count;
extern atomic_long_t fs_time;
extern atomic_long_t fs_count;
extern ktime_t fs_start;
extern atomic_long_t dio_time;
extern atomic_long_t dio_count;
extern atomic_long_t block_time;
extern atomic_long_t block_count;

/*----zhengxd kernel stat*/

int iomap_dio_iopoll(struct kiocb *kiocb, bool spin)
{
	struct request_queue *q = READ_ONCE(kiocb->private);

	if (!q)
		return 0;
	return blk_poll(q, READ_ONCE(kiocb->ki_cookie), spin);
}
EXPORT_SYMBOL_GPL(iomap_dio_iopoll);

static void iomap_dio_submit_bio(struct iomap_dio *dio, struct iomap *iomap,
		struct bio *bio, loff_t pos)
{
	atomic_inc(&dio->ref);

	if (dio->iocb->ki_flags & IOCB_HIPRI)
		bio_set_polled(bio, dio->iocb);
	
	// atomic_long_inc(&fs_count);
	// atomic_long_add(ktime_sub(ktime_get(), fs_start), &fs_time);

	dio->submit.last_queue = bdev_get_queue(iomap->bdev);
	if (dio->dops && dio->dops->submit_io)
		dio->submit.cookie = dio->dops->submit_io(
				file_inode(dio->iocb->ki_filp),
				iomap, bio, pos);
	else
		dio->submit.cookie = submit_bio(bio);
		
}

ssize_t iomap_dio_complete(struct iomap_dio *dio)
{
	const struct iomap_dio_ops *dops = dio->dops;
	struct kiocb *iocb = dio->iocb;
	struct inode *inode = file_inode(iocb->ki_filp);
	loff_t offset = iocb->ki_pos;
	ssize_t ret = dio->error;

	if (dops && dops->end_io)
		ret = dops->end_io(iocb, dio->size, ret, dio->flags);

	if (likely(!ret)) {
		ret = dio->size;
		/* check for short read */
		if (offset + ret > dio->i_size &&
		    !(dio->flags & IOMAP_DIO_WRITE))
			ret = dio->i_size - offset;
		iocb->ki_pos += ret;
	}

	/*
	 * Try again to invalidate clean pages which might have been cached by
	 * non-direct readahead, or faulted in by get_user_pages() if the source
	 * of the write was an mmap'ed region of the file we're writing.  Either
	 * one is a pretty crazy thing to do, so we don't support it 100%.  If
	 * this invalidation fails, tough, the write still worked...
	 *
	 * And this page cache invalidation has to be after ->end_io(), as some
	 * filesystems convert unwritten extents to real allocations in
	 * ->end_io() when necessary, otherwise a racing buffer read would cache
	 * zeros from unwritten extents.
	 */
	if (!dio->error && dio->size &&
	    (dio->flags & IOMAP_DIO_WRITE) && inode->i_mapping->nrpages) {
		int err;
		err = invalidate_inode_pages2_range(inode->i_mapping,
				offset >> PAGE_SHIFT,
				(offset + dio->size - 1) >> PAGE_SHIFT);
		if (err)
			dio_warn_stale_pagecache(iocb->ki_filp);
	}

	inode_dio_end(file_inode(iocb->ki_filp));
	/*
	 * If this is a DSYNC write, make sure we push it to stable storage now
	 * that we've written data.
	 */
	if (ret > 0 && (dio->flags & IOMAP_DIO_NEED_SYNC))
		ret = generic_write_sync(iocb, ret);

	kfree(dio);

	return ret;
}
EXPORT_SYMBOL_GPL(iomap_dio_complete);

static void iomap_dio_complete_work(struct work_struct *work)
{
	struct iomap_dio *dio = container_of(work, struct iomap_dio, aio.work);
	struct kiocb *iocb = dio->iocb;

	iocb->ki_complete(iocb, iomap_dio_complete(dio), 0);
}

/*
 * Set an error in the dio if none is set yet.  We have to use cmpxchg
 * as the submission context and the completion context(s) can race to
 * update the error.
 */
static inline void iomap_dio_set_error(struct iomap_dio *dio, int ret)
{
	cmpxchg(&dio->error, 0, ret);
}

static void iomap_dio_bio_end_io(struct bio *bio)
{
	struct iomap_dio *dio = bio->bi_private;
	bool should_dirty = (dio->flags & IOMAP_DIO_DIRTY);

	if(bio->hit_enabled){
		kfree(bio->hit);
		bio->hit = NULL;
	}
	if (bio->bi_status){
		iomap_dio_set_error(dio, blk_status_to_errno(bio->bi_status));
	}
	if (atomic_dec_and_test(&dio->ref)) {
		if (dio->wait_for_completion) {
			struct task_struct *waiter = dio->submit.waiter;
			WRITE_ONCE(dio->submit.waiter, NULL);
			blk_wake_io_task(waiter);
		} else if (dio->flags & IOMAP_DIO_WRITE) {
			struct inode *inode = file_inode(dio->iocb->ki_filp);

			INIT_WORK(&dio->aio.work, iomap_dio_complete_work);
			queue_work(inode->i_sb->s_dio_done_wq, &dio->aio.work);
		} else {
			iomap_dio_complete_work(&dio->aio.work);
		}
	}

	if (should_dirty) {
		bio_check_pages_dirty(bio);
	} else {
		bio_release_pages(bio, false);
		bio_put(bio);
	}
}

static void
iomap_dio_zero(struct iomap_dio *dio, struct iomap *iomap, loff_t pos,
		unsigned len)
{
	struct page *page = ZERO_PAGE(0);
	int flags = REQ_SYNC | REQ_IDLE;
	struct bio *bio;

	bio = bio_alloc(GFP_KERNEL, 1);
	bio_set_dev(bio, iomap->bdev);
	bio->bi_iter.bi_sector = iomap_sector(iomap, pos);
	bio->bi_private = dio;
	bio->bi_end_io = iomap_dio_bio_end_io;

	get_page(page);
	__bio_add_page(bio, page, len, 0);
	bio_set_op_attrs(bio, REQ_OP_WRITE, flags);
	iomap_dio_submit_bio(dio, iomap, bio, pos);
}

/*
 * Figure out the bio's operation flags from the dio request, the
 * mapping, and whether or not we want FUA.  Note that we can end up
 * clearing the WRITE_FUA flag in the dio request.
 */
static inline unsigned int
iomap_dio_bio_opflags(struct iomap_dio *dio, struct iomap *iomap, bool use_fua)
{
	unsigned int opflags = REQ_SYNC | REQ_IDLE;

	if (!(dio->flags & IOMAP_DIO_WRITE)) {
		WARN_ON_ONCE(iomap->flags & IOMAP_F_ZONE_APPEND);
		return REQ_OP_READ;
	}

	if (iomap->flags & IOMAP_F_ZONE_APPEND)
		opflags |= REQ_OP_ZONE_APPEND;
	else
		opflags |= REQ_OP_WRITE;

	if (use_fua)
		opflags |= REQ_FUA;
	else
		dio->flags &= ~IOMAP_DIO_WRITE_FUA;

	return opflags;
}


static loff_t
iomap_dio_bio_actor(struct inode *inode, loff_t pos, loff_t length,
		struct iomap_dio *dio, struct iomap *iomap)
{
	unsigned int blkbits = blksize_bits(bdev_logical_block_size(iomap->bdev));
	unsigned int fs_block_size = i_blocksize(inode), pad;
	unsigned int align = iov_iter_alignment(dio->submit.iter);
	unsigned int bio_opf;
	struct bio *bio;
	bool need_zeroout = false;
	bool use_fua = false;
	int nr_pages, ret = 0;
	size_t copied = 0;
	size_t orig_count;

	if ((pos | length | align) & ((1 << blkbits) - 1))
		return -EINVAL;

	if (iomap->type == IOMAP_UNWRITTEN) {
		dio->flags |= IOMAP_DIO_UNWRITTEN;
		need_zeroout = true;
	}

	if (iomap->flags & IOMAP_F_SHARED)
		dio->flags |= IOMAP_DIO_COW;

	if (iomap->flags & IOMAP_F_NEW) {
		need_zeroout = true;
	} else if (iomap->type == IOMAP_MAPPED) {
		/*
		 * Use a FUA write if we need datasync semantics, this is a pure
		 * data IO that doesn't require any metadata updates (including
		 * after IO completion such as unwritten extent conversion) and
		 * the underlying device supports FUA. This allows us to avoid
		 * cache flushes on IO completion.
		 */
		if (!(iomap->flags & (IOMAP_F_SHARED|IOMAP_F_DIRTY)) &&
		    (dio->flags & IOMAP_DIO_WRITE_FUA) &&
		    blk_queue_fua(bdev_get_queue(iomap->bdev)))
			use_fua = true;
	}

	/*
	 * Save the original count and trim the iter to just the extent we
	 * are operating on right now.  The iter will be re-expanded once
	 * we are done.
	 */
	orig_count = iov_iter_count(dio->submit.iter);
	//zhengxd： disable truncate
	if(!dio->iocb->hit_enabled)
		iov_iter_truncate(dio->submit.iter, length);

	if (!iov_iter_count(dio->submit.iter))
		goto out;

	if (need_zeroout) {
		/* zero out from the start of the block to the write offset */
		pad = pos & (fs_block_size - 1);
		if (pad)
			iomap_dio_zero(dio, iomap, pos - pad, pad);
	}

	/*
	 * Set the operation flags early so that bio_iov_iter_get_pages
	 * can set up the page vector appropriately for a ZONE_APPEND
	 * operation.
	 */
	bio_opf = iomap_dio_bio_opflags(dio, iomap, use_fua);
	//zhengxd: max: 256 page; return the number of page alignments
	nr_pages = bio_iov_vecs_to_alloc(dio->submit.iter, BIO_MAX_VECS);
	do {
		size_t n;
		if (dio->error) {
			iov_iter_revert(dio->submit.iter, copied);
			copied = ret = 0;
			goto out;
		}
		//zhengxd: kernel stat
		// ktime_t bio_start = ktime_get();

		bio = bio_alloc(GFP_KERNEL, nr_pages);
		bio_set_dev(bio, iomap->bdev);
		bio->bi_iter.bi_sector = iomap_sector(iomap, pos);
		bio->bi_write_hint = dio->iocb->ki_hint;
		bio->bi_ioprio = dio->iocb->ki_ioprio;
		bio->bi_private = dio;
		bio->bi_end_io = iomap_dio_bio_end_io;
		bio->bi_opf = bio_opf;

		

		//zhengxd: xrp init
		//zhengxd: bio_iov_iter_get_page need hit_enabled
		bio->hit_enabled = dio->iocb->hit_enabled;
		bio->xrp_buffer_size = nr_pages;

		// zhengxd: kernel stat
		// if(bio->hit_enabled){
			// atomic_long_inc(&bio_count);
			// atomic_long_add(ktime_sub(ktime_get(), bio_start), &bio_time);
		// }

		// zhengxd: kernel stat
		// ktime_t get_page_start = ktime_get();

		ret = bio_iov_iter_get_pages(bio, dio->submit.iter);
		// zhengxd: kernel stat
		// if(bio->hit_enabled){
			// atomic_long_inc(&get_page_count);
			// atomic_long_add(ktime_sub(ktime_get(), get_page_start), &get_page_time);
		// }
		if (unlikely(ret)) {
			/*
			 * We have to stop part way through an IO. We must fall
			 * through to the sub-block tail zeroing here, otherwise
			 * this short IO may expose stale data in the tail of
			 * the block we haven't written data to.
			 */
			bio_put(bio);
			goto zero_tail;
		}

		//zhengxd: init bi_size with x2rp_data_len
		if(bio->hit_enabled) {
			bio->bi_iter.bi_size = dio->iocb->data_len;
		}
		if (bio->hit_enabled) {
			//zhengxd: kernel stat
			// ktime_t iomap_start = ktime_get();
			bio->hit = kmalloc(sizeof(struct hitchhike), GFP_KERNEL);
			if(!bio->hit)
				return -ENOMEM;
			if (unlikely(copy_from_user(bio->hit, dio->iocb->hit, sizeof(struct hitchhike)))){
				return -EFAULT;
			}

			loff_t len;
			int iter;
			if(bio->hit->in_use){
				for(iter = 0; iter <= bio->hit->max; iter++){
					//zhengxd: size always == 4096
					len = 4096;
					pos = bio->hit->addr[iter];
					struct iomap iomap_t = { .type = IOMAP_HOLE };
					struct iomap srcmap_t = { .type = IOMAP_HOLE };
					ret = dio->iocb->ops->iomap_begin(inode, pos, len, iomap->flags, &iomap_t, &srcmap_t);
					if (ret)
						return ret;
					// lba in 512B
					bio->hit->addr[iter] = iomap_sector(&iomap_t, pos);
					// zhengxd: kernel stat
					// atomic_long_inc(&iomap_hit_count);
				}
			}
			// zhengxd: kernel stat
			// atomic_long_add(ktime_sub(ktime_get(), iomap_start), &iomap_hit_time);
		}

		//zhengxd: nr_pages > 256 (error)
		n = bio->bi_iter.bi_size;
		if (dio->flags & IOMAP_DIO_WRITE) {
			task_io_account_write(n);
		} else {
			if (dio->flags & IOMAP_DIO_DIRTY)
			//zhengxd: dirty lock(release in iomap_dio_bio_end_io)
				bio_set_pages_dirty(bio);
		}
		//zhengxd： dio->size initial value is 0
		dio->size += n;
		copied += n;

		nr_pages = bio_iov_vecs_to_alloc(dio->submit.iter,
						 BIO_MAX_VECS);
		iomap_dio_submit_bio(dio, iomap, bio, pos);
		pos += n;
		// if(bio->hit_enabled){
		// 	printk(KERN_DEBUG "----iomap: nr_pages is %d----\n",nr_pages);
		// }
	} while (nr_pages);

	/*
	 * We need to zeroout the tail of a sub-block write if the extent type
	 * requires zeroing or the write extends beyond EOF. If we don't zero
	 * the block tail in the latter case, we can expose stale data via mmap
	 * reads of the EOF block.
	 */
zero_tail:
	if (need_zeroout ||
	    ((dio->flags & IOMAP_DIO_WRITE) && pos >= i_size_read(inode))) {
		/* zero out from the end of the write to the end of the block */
		pad = pos & (fs_block_size - 1);
		if (pad)
			iomap_dio_zero(dio, iomap, pos, fs_block_size - pad);
	}
out:
	/* Undo iter limitation to current extent */
	iov_iter_reexpand(dio->submit.iter, orig_count - copied);
	if (copied)
		return copied;
	return ret;
}

static loff_t
iomap_dio_hole_actor(loff_t length, struct iomap_dio *dio)
{
	length = iov_iter_zero(length, dio->submit.iter);
	dio->size += length;
	return length;
}

static loff_t
iomap_dio_inline_actor(struct inode *inode, loff_t pos, loff_t length,
		struct iomap_dio *dio, struct iomap *iomap)
{
	struct iov_iter *iter = dio->submit.iter;
	size_t copied;

	BUG_ON(pos + length > PAGE_SIZE - offset_in_page(iomap->inline_data));

	if (dio->flags & IOMAP_DIO_WRITE) {
		loff_t size = inode->i_size;

		if (pos > size)
			memset(iomap->inline_data + size, 0, pos - size);
		copied = copy_from_iter(iomap->inline_data + pos, length, iter);
		if (copied) {
			if (pos + copied > size)
				i_size_write(inode, pos + copied);
			mark_inode_dirty(inode);
		}
	} else {
		copied = copy_to_iter(iomap->inline_data + pos, length, iter);
	}
	dio->size += copied;
	return copied;
}

static loff_t
iomap_dio_actor(struct inode *inode, loff_t pos, loff_t length,
		void *data, struct iomap *iomap, struct iomap *srcmap)
{
	struct iomap_dio *dio = data;

	switch (iomap->type) {
	case IOMAP_HOLE:
		if (WARN_ON_ONCE(dio->flags & IOMAP_DIO_WRITE))
			return -EIO;
		return iomap_dio_hole_actor(length, dio);
	case IOMAP_UNWRITTEN:
		if (!(dio->flags & IOMAP_DIO_WRITE))
			return iomap_dio_hole_actor(length, dio);
		return iomap_dio_bio_actor(inode, pos, length, dio, iomap);
	// zhengxd: mapped address
	case IOMAP_MAPPED:
		return iomap_dio_bio_actor(inode, pos, length, dio, iomap);
	case IOMAP_INLINE:
		return iomap_dio_inline_actor(inode, pos, length, dio, iomap);
	case IOMAP_DELALLOC:
		/*
		 * DIO is not serialised against mmap() access at all, and so
		 * if the page_mkwrite occurs between the writeback and the
		 * iomap_apply() call in the DIO path, then it will see the
		 * DELALLOC block that the page-mkwrite allocated.
		 */
		pr_warn_ratelimited("Direct I/O collision with buffered writes! File: %pD4 Comm: %.20s\n",
				    dio->iocb->ki_filp, current->comm);
		return -EIO;
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}


/*
 * iomap_dio_rw() always completes O_[D]SYNC writes regardless of whether the IO
 * is being issued as AIO or not.  This allows us to optimise pure data writes
 * to use REQ_FUA rather than requiring generic_write_sync() to issue a
 * REQ_FLUSH post write. This is slightly tricky because a single request here
 * can be mapped into multiple disjoint IOs and only a subset of the IOs issued
 * may be pure data writes. In that case, we still need to do a full data sync
 * completion.
 *
 * Returns -ENOTBLK In case of a page invalidation invalidation failure for
 * writes.  The callers needs to fall back to buffered I/O in this case.
 */
struct iomap_dio *
__iomap_dio_rw(struct kiocb *iocb, struct iov_iter *iter,
		const struct iomap_ops *ops, const struct iomap_dio_ops *dops,
		unsigned int dio_flags)
{
	struct address_space *mapping = iocb->ki_filp->f_mapping;
	// zhengxd: get file inode(iomap get a range address map with inode )
	struct inode *inode = file_inode(iocb->ki_filp);
	//zhengxd: get buffer size
	size_t count = iov_iter_count(iter);
	//zhengxd: get data size
	size_t data_len = iocb->data_len;
	loff_t pos = iocb->ki_pos;
	// loff_t end = iocb->ki_pos + data_len - 1, ret = 0;
	loff_t end, ret = 0;
	if(iocb->hit_enabled){
		//zhengxd: new end init
		end = iocb->ki_pos + data_len - 1;
	} else {
		//zhengxd: old init end
		end = iocb->ki_pos + count - 1;
	}

	bool wait_for_completion =
		is_sync_kiocb(iocb) || (dio_flags & IOMAP_DIO_FORCE_WAIT);
	unsigned int iomap_flags = IOMAP_DIRECT;
	struct blk_plug plug;
	struct iomap_dio *dio;

	if (!count)
		return NULL;
	//zhengxd: datalen assert
	if(iocb->hit_enabled && !data_len)
		return NULL;

	// zhengxd: kernel stat
	// ktime_t dio_start = ktime_get();	

	dio = kmalloc(sizeof(*dio), GFP_KERNEL);
	if (!dio)
		return ERR_PTR(-ENOMEM);

	dio->iocb = iocb;
	atomic_set(&dio->ref, 1);
	dio->size = 0;
	dio->i_size = i_size_read(inode);
	dio->dops = dops;
	dio->error = 0;
	dio->flags = 0;

	dio->submit.iter = iter;
	dio->submit.waiter = current;
	dio->submit.cookie = BLK_QC_T_NONE;
	dio->submit.last_queue = NULL;

	// zhengxd: kernel stat
	// atomic_long_inc(&dio_count);
	// atomic_long_add(ktime_sub(ktime_get(), dio_start), &dio_time);

	if (iov_iter_rw(iter) == READ) {
		if (pos >= dio->i_size)
			goto out_free_dio;
		// zhengxd: set dirty flag, x2rp dont set
		if (iter_is_iovec(iter) && !iocb->hit_enabled)
			dio->flags |= IOMAP_DIO_DIRTY;
	} else {
		iomap_flags |= IOMAP_WRITE;
		dio->flags |= IOMAP_DIO_WRITE;

		/* for data sync or sync, we need sync completion processing */
		if (iocb->ki_flags & IOCB_DSYNC)
			dio->flags |= IOMAP_DIO_NEED_SYNC;

		/*
		 * For datasync only writes, we optimistically try using FUA for
		 * this IO.  Any non-FUA write that occurs will clear this flag,
		 * hence we know before completion whether a cache flush is
		 * necessary.
		 */
		if ((iocb->ki_flags & (IOCB_DSYNC | IOCB_SYNC)) == IOCB_DSYNC)
			dio->flags |= IOMAP_DIO_WRITE_FUA;
	}

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (filemap_range_has_page(mapping, pos, end)) {
			ret = -EAGAIN;
			goto out_free_dio;
		}
		iomap_flags |= IOMAP_NOWAIT;
	}

	if (dio_flags & IOMAP_DIO_OVERWRITE_ONLY) {
		ret = -EAGAIN;
		if (pos >= dio->i_size || pos + count > dio->i_size)
			goto out_free_dio;
		iomap_flags |= IOMAP_OVERWRITE_ONLY;
	}
	//zhengxd: fixme : hitchhike need wait
	// zhengxd: kernel stat
	// ktime_t filemap_start = ktime_get();
	ret = filemap_write_and_wait_range(mapping, pos, end);
	// atomic_long_inc(&filemap_wait_count);
	// atomic_long_add(ktime_sub(ktime_get(), filemap_start), &filemap_wait_time);

	if (ret)
		goto out_free_dio;

	if (iov_iter_rw(iter) == WRITE) {
		/*
		 * Try to invalidate cache pages for the range we are writing.
		 * If this invalidation fails, let the caller fall back to
		 * buffered I/O.
		 */
		if (invalidate_inode_pages2_range(mapping, pos >> PAGE_SHIFT,
				end >> PAGE_SHIFT)) {
			trace_iomap_dio_invalidate_fail(inode, pos, count);
			ret = -ENOTBLK;
			goto out_free_dio;
		}

		if (!wait_for_completion && !inode->i_sb->s_dio_done_wq) {
			ret = sb_init_dio_done_wq(inode->i_sb);
			if (ret < 0)
				goto out_free_dio;
		}
	}

	inode_dio_begin(inode);

	blk_start_plug(&plug);
	do {
		//zhengxd: pass datalen instead of buffer count； buffer count pass with dio->submit_iter
		// ret = iomap_apply(inode, pos, data_len, iomap_flags, ops, dio,
		// 					iomap_dio_actor);
		if(iocb->hit_enabled){
			ret = iomap_apply(inode, pos, data_len, iomap_flags, ops, dio,
					iomap_dio_actor);
		}else{
			ret = iomap_apply(inode, pos, count, iomap_flags, ops, dio,
					iomap_dio_actor);
		}
		if (ret <= 0) {
			/* magic error code to fall back to buffered I/O */
			if (ret == -ENOTBLK) {
				wait_for_completion = true;
				ret = 0;
			}
			break;
		}
		pos += ret;
		//zhengxd: if read out of file, roll back
		if (iov_iter_rw(iter) == READ && pos >= dio->i_size) {
			/*
			 * We only report that we've read data up to i_size.
			 * Revert iter to a state corresponding to that as
			 * some callers (such as splice code) rely on it.
			 */
			iov_iter_revert(iter, pos - dio->i_size);
			break;
		}
	/*zhengxd: the LBA of req must be continuous. 
	 *in V1.0 we just ignore this problem , and set host io is 4K
	 *so, the do-while loop just execute once
	 */
		if(iocb->hit_enabled){
			iov_iter_reexpand(iter, 0);
		}
	} while ((count = iov_iter_count(iter)) > 0);
	blk_finish_plug(&plug);

	if (ret < 0)
		iomap_dio_set_error(dio, ret);

	/*
	 * If all the writes we issued were FUA, we don't need to flush the
	 * cache on IO completion. Clear the sync flag for this case.
	 */
	if (dio->flags & IOMAP_DIO_WRITE_FUA)
		dio->flags &= ~IOMAP_DIO_NEED_SYNC;

	WRITE_ONCE(iocb->ki_cookie, dio->submit.cookie);
	WRITE_ONCE(iocb->private, dio->submit.last_queue);

	/*
	 * We are about to drop our additional submission reference, which
	 * might be the last reference to the dio.  There are three different
	 * ways we can progress here:
	 *
	 *  (a) If this is the last reference we will always complete and free
	 *	the dio ourselves.
	 *  (b) If this is not the last reference, and we serve an asynchronous
	 *	iocb, we must never touch the dio after the decrement, the
	 *	I/O completion handler will complete and free it.
	 *  (c) If this is not the last reference, but we serve a synchronous
	 *	iocb, the I/O completion handler will wake us up on the drop
	 *	of the final reference, and we will complete and free it here
	 *	after we got woken by the I/O completion handler.
	 */
	dio->wait_for_completion = wait_for_completion;
	if (!atomic_dec_and_test(&dio->ref)) {
		if (!wait_for_completion)
			return ERR_PTR(-EIOCBQUEUED);

		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!READ_ONCE(dio->submit.waiter))
				break;

			if (!(iocb->ki_flags & IOCB_HIPRI) ||
			    !dio->submit.last_queue ||
			    !blk_poll(dio->submit.last_queue,
					 dio->submit.cookie, true))
				blk_io_schedule();
		}
		__set_current_state(TASK_RUNNING);
	}

	return dio;

out_free_dio:
	kfree(dio);
	if (ret)
		return ERR_PTR(ret);
	return NULL;
}
EXPORT_SYMBOL_GPL(__iomap_dio_rw);

ssize_t
iomap_dio_rw(struct kiocb *iocb, struct iov_iter *iter,
		const struct iomap_ops *ops, const struct iomap_dio_ops *dops,
		unsigned int dio_flags)
{
	struct iomap_dio *dio;
	if(iocb->hit_enabled){
		iocb->ops = ops;
	}

	dio = __iomap_dio_rw(iocb, iter, ops, dops, dio_flags);
	if (IS_ERR_OR_NULL(dio))
		return PTR_ERR_OR_ZERO(dio);
	return iomap_dio_complete(dio);
}
EXPORT_SYMBOL_GPL(iomap_dio_rw);
