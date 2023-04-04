/*
 * expand.c --- expand an ext2fs directory
 *
 * Copyright (C) 1993, 1994, 1995, 1996, 1997, 1998, 1999  Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Library
 * General Public License, version 2.
 * %End-Header%
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ext2_fs.h"
#include "ext2fs.h"
#include "ext2fsP.h"

struct expand_dir_struct {
	int		done;
	int		newblocks;
	blk64_t		goal;
	errcode_t	err;
	ext2_ino_t	dir;
};

static int expand_dir_proc(ext2_filsys	fs,
			   blk64_t	*blocknr,
			   e2_blkcnt_t	blockcnt,
			   blk64_t	ref_block EXT2FS_ATTR((unused)),
			   int		ref_offset EXT2FS_ATTR((unused)),
			   void		*priv_data)
{
	struct expand_dir_struct *es = (struct expand_dir_struct *) priv_data;
	blk64_t	new_blk;
	char		*block;
	errcode_t	retval;

	if (*blocknr) {
		if (blockcnt >= 0)
			es->goal = *blocknr;
		return 0;
	}
	if (blockcnt &&
	    (EXT2FS_B2C(fs, es->goal) == EXT2FS_B2C(fs, es->goal+1)))
		new_blk = es->goal+1;
	else {
		es->goal &= ~EXT2FS_CLUSTER_MASK(fs);
		retval = ext2fs_new_block2(fs, es->goal, 0, &new_blk);
		if (retval) {
			es->err = retval;
			return BLOCK_ABORT;
		}
		es->newblocks++;
		ext2fs_block_alloc_stats2(fs, new_blk, +1);
	}
	if (blockcnt > 0) {
		retval = ext2fs_new_dir_block(fs, 0, 0, &block);
		if (retval) {
			es->err = retval;
			return BLOCK_ABORT;
		}
		es->done = 1;
		retval = ext2fs_write_dir_block4(fs, new_blk, block, 0,
						 es->dir);
		ext2fs_free_mem(&block);
	} else
		retval = ext2fs_zero_blocks2(fs, new_blk, 1, NULL, NULL);
	if (blockcnt >= 0)
		es->goal = new_blk;
	if (retval) {
		es->err = retval;
		return BLOCK_ABORT;
	}
	*blocknr = new_blk;

	if (es->done)
		return (BLOCK_CHANGED | BLOCK_ABORT);
	else
		return BLOCK_CHANGED;
}

struct ext2_fake_dirent
{
	__le32 inode;
	__le16 rec_len;
	__u8 name_len;
	__u8 file_type;
};

struct ext2_dx_root
{
	struct ext2_fake_dirent dot;
	char dot_name[4];
	struct ext2_fake_dirent dotdot;
	char dotdot_name[4];
	struct ext2_dx_root_info info;
	struct ext2_dx_entry entries[];
};

#define EXT4_MAX_REC_LEN		((1<<16)-1)

static unsigned int get_rec_len(ext2_filsys fs, unsigned int len) {
    if (fs->blocksize < 65536)
        return len;
    else if (len == EXT4_MAX_REC_LEN || len == 0)
        return fs->blocksize;
    else
        return (len & 65532) | ((len & 3) << 16);
}

static struct ext2_dir_entry_2 *get_next_entry(ext2_filsys fs, struct ext2_dir_entry_2 *p) {
    return (struct ext2_dir_entry_2 *) ((char *) p + get_rec_len(fs, p->rec_len));
}

static errcode_t ext2fs_expand_dir2(ext2_filsys fs, ext2_ino_t dir);

/*
 * This converts a one block unindexed directory to a 2 block indexed
 * directory, and adds the dentry to the indexed directory.
 */
static errcode_t make_indexed_dir(ext2_filsys fs, ext2_ino_t dir, struct ext2_inode *diri) {
    errcode_t retval;
    int csum_size = 0;
    unsigned int blocksize = fs->blocksize;
    struct ext2_dx_root *root;
    struct ext2_fake_dirent *fde;
    struct ext2_dir_entry_2 *de, *de2;
    unsigned int len;
    char *data2, *top;
    struct ext2_dx_entry *entries;
    struct dx_lookup_info dx_info;

    if (ext2fs_has_feature_metadata_csum(fs->super))
        csum_size = sizeof(struct ext2_dir_entry_tail);

    if ((retval = ext2fs_expand_dir2(fs, dir)) != 0)
        return retval;
    if ((retval = ext2fs_read_inode(fs, dir, diri)) != 0)
        return retval;

    dx_info.levels = 2;
    for (int i = 0; i < dx_info.levels; i++) {
        if ((retval = alloc_dx_frame(fs, dx_info.frames + i)) != 0)
            return retval;
        load_logical_dir_block(fs, dir, diri, i, &(dx_info.frames[i].pblock), dx_info.frames[i].buf);
    }

    /* The 0th block becomes the root, move the dirents out */
    root = (struct ext2_dx_root *) (dx_info.frames[0].buf);
    fde = &(root->dotdot);
    de = (struct ext2_dir_entry_2 *) ((char *) fde + get_rec_len(fs, fde->rec_len));
    if ((char *) de >= (((char *) root) + blocksize))
        return EXT2_FILSYS_CORRUPTED;
    len = ((char *) root) + (blocksize - csum_size) - (char *) de;
    data2 = dx_info.frames[1].buf;
    memcpy(data2, de, len);
    memset(de, 0, len);
    de = (struct ext2_dir_entry_2 *) data2;
    top = data2 + len;
    while ((char *) (de2 = get_next_entry(fs, de)) < top)
        de = de2;
    ext2fs_set_rec_len(fs, data2 + (blocksize - csum_size) - (char *) de, (struct ext2_dir_entry *)de);
    if (csum_size)
        ext2fs_initialize_dirent_tail(fs, EXT2_DIRENT_TAIL(data2, blocksize));

    /* Initialize the root; the dot dirents already exist */
    diri->i_flags |= EXT2_INDEX_FL;
    de = (struct ext2_dir_entry_2 *) (&root->dotdot);
    ext2fs_set_rec_len(fs, blocksize - EXT2_DIR_REC_LEN(2), (struct ext2_dir_entry *)de);
    memset(&root->info, 0, sizeof(root->info));
    root->info.info_length = sizeof(root->info);
    if (ext4_hash_in_dirent(diri)) {
        root->info.hash_version = EXT2_HASH_SIPHASH;
    } else {
        root->info.hash_version = fs->super->s_def_hash_version;
    }
    entries = root->entries;
    entries->block = ext2fs_cpu_to_le32(1);
    ((struct ext2_dx_countlimit *) entries)->count = ext2fs_cpu_to_le16(1);
    ((struct ext2_dx_countlimit *) entries)->limit = ext2fs_cpu_to_le16((blocksize - (32 + csum_size)) / sizeof(struct ext2_dx_entry));

    /* write out blocks */
    for (int i = 0; i < dx_info.levels; i++)
        ext2fs_write_dir_block4(fs, dx_info.frames[i].pblock, dx_info.frames[i].buf, 0, dir);
    /* write out inode (dx_root) */
    if ((retval = ext2fs_write_inode(fs, dir, diri)) != 0)
        return retval;

    /* free frames */
    dx_release(&dx_info);
    return 0;
}

static errcode_t ext2fs_expand_dir2(ext2_filsys fs, ext2_ino_t dir)
{
	errcode_t	retval;
	struct expand_dir_struct es;
	struct ext2_inode	inode;

	EXT2_CHECK_MAGIC(fs, EXT2_ET_MAGIC_EXT2FS_FILSYS);

	if (!(fs->flags & EXT2_FLAG_RW))
		return EXT2_ET_RO_FILSYS;

	if (!fs->block_map)
		return EXT2_ET_NO_BLOCK_BITMAP;

	retval = ext2fs_check_directory(fs, dir);
	if (retval)
		return retval;

	retval = ext2fs_read_inode(fs, dir, &inode);
	if (retval)
		return retval;

	es.done = 0;
	es.err = 0;
	es.goal = ext2fs_find_inode_goal(fs, dir, &inode, 0);
	es.newblocks = 0;
	es.dir = dir;

	retval = ext2fs_block_iterate3(fs, dir, BLOCK_FLAG_APPEND,
				       0, expand_dir_proc, &es);
	if (retval == EXT2_ET_INLINE_DATA_CANT_ITERATE)
		return ext2fs_inline_data_expand(fs, dir);

	if (es.err)
		return es.err;
	if (!es.done)
		return EXT2_ET_EXPAND_DIR_ERR;

	/*
	 * Update the size and block count fields in the inode.
	 */
	retval = ext2fs_read_inode(fs, dir, &inode);
	if (retval)
		return retval;

	retval = ext2fs_inode_size_set(fs, &inode,
				       EXT2_I_SIZE(&inode) + fs->blocksize);
	if (retval)
		return retval;
	ext2fs_iblk_add_blocks(fs, &inode, es.newblocks);

	retval = ext2fs_write_inode(fs, dir, &inode);
	if (retval)
		return retval;

	return 0;
}

errcode_t ext2fs_expand_dir(ext2_filsys fs, ext2_ino_t dir) {
    errcode_t retval;
    struct ext2_inode inode;

    retval = ext2fs_read_inode(fs, dir, &inode);
    if (retval)
        return retval;

    unsigned int blocks = inode.i_size >> (fs->super->s_log_block_size + EXT2_MIN_BLOCK_LOG_SIZE);

    /* htree */
    if (blocks == 1 && ext2fs_has_feature_dir_index(fs->super) && !(inode.i_flags & EXT2_INDEX_FL))
        return make_indexed_dir(fs, dir, &inode);

    return ext2fs_expand_dir2(fs, dir);
}