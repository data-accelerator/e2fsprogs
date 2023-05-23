/*
 * lookup.c --- ext2fs directory lookup operations
 *
 * Copyright (C) 1993, 1994, 1994, 1995 Theodore Ts'o.
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

struct lookup_struct  {
    const char  *name;
    int         len;
    ext2_ino_t  *inode;
    int         found;
};

#ifdef __TURBOC__
 #pragma argsused
#endif
static int lookup_proc(ext2_ino_t dir EXT2FS_ATTR((unused)),
               int entru EXT2FS_ATTR((unused)),
               struct ext2_dir_entry *dirent,
               int	offset EXT2FS_ATTR((unused)),
               int	blocksize EXT2FS_ATTR((unused)),
               char	*buf EXT2FS_ATTR((unused)),
               void	*priv_data)
{
    struct lookup_struct *ls = (struct lookup_struct *) priv_data;

    if (dirent->inode == 0 /* useless? */)
        return 0;
    if (ls->len != ext2fs_dirent_name_len(dirent))
        return 0;
    if (strncmp(ls->name, dirent->name, ext2fs_dirent_name_len(dirent)))
        return 0;
    *ls->inode = dirent->inode;
    ls->found++;
    return DIRENT_ABORT;
}

/**
 * @return 0 if the caller should continue to search, or errcode
*/
static int htree_next_block(ext2_filsys fs, ext2_ino_t dir, struct ext2_inode *diri, struct dx_lookup_info *info) {
    errcode_t retval = 0;
    struct dx_frame *p;
    int num_frames = 0;

    p = &(info->frames[info->levels - 1]);
    /*
     * Find the next leaf page by incrementing the frame pointer.
     * If we run out of entries in the interior node, loop around and
     * increment pointer in the parent node.  When we break out of
     * this loop, num_frames indicates the number of interior
     * nodes need to be read.
     */
    while (1) {
        int count = ext2fs_le16_to_cpu(p->head->count);
        if (++(p->at) < p->entries + count) break;
        if (p == info->frames) return EXT2_ET_FILE_NOT_FOUND;
        num_frames++;
        p--;
    }

    __u32 next_hash = ext2fs_le32_to_cpu(p->at->hash);
    if ((info->hash & 1) == 0 /* useless? */ && (next_hash & ~1) != info->hash) {
        return EXT2_ET_FILE_NOT_FOUND;
    }

    while (num_frames--) {
        e2_blkcnt_t blockcnt = ext2fs_le32_to_cpu(info->frames[info->levels-1].at->block) & 0x0fffffff;
        p++;
        if ((retval = load_logical_dir_block(fs, dir, diri, blockcnt, &(p->pblock), p->buf)) != 0) {
            return retval;
        }
        if ((retval = ext2fs_get_dx_countlimit(fs, p->buf, &(p->head), NULL)) != 0) {
            return retval;
        }
        int count = ext2fs_le16_to_cpu(p->head->count);
        int limit = ext2fs_le16_to_cpu(p->head->limit);
        if (!count || count > limit) {
            return EXT2_ET_DIR_CORRUPTED;
        }
        p->at = p->entries = (struct ext2_dx_entry *) (p->head);
    }
    return 0;
}

static errcode_t dx_namei(ext2_filsys fs, ext2_ino_t dir, struct ext2_inode *diri, const char *name, int namelen, char *buf, ext2_ino_t *res_inode) {
    struct dx_lookup_info dx_info;
    errcode_t retval = 0;
    blk64_t leaf_pblk;
    void *block_buf = NULL;
    if (buf == NULL) {
        retval = ext2fs_get_mem(fs->blocksize, &block_buf);
        if (retval)
            goto cleanup;
        buf = block_buf;
    }

    dx_info.name = name;
    dx_info.namelen = namelen;
    if ((retval = dx_lookup(fs, dir, diri, &dx_info)) != 0)
        goto cleanup;

    do {
        e2_blkcnt_t blockcnt = ext2fs_le32_to_cpu(dx_info.frames[dx_info.levels-1].at->block) & 0x0fffffff;

        if ((retval = load_logical_dir_block(fs, dir, diri, blockcnt, &leaf_pblk, buf)) != 0)
            goto cleanup;

        struct dir_context ctx;
        struct lookup_struct ls;
        ctx.errcode = 0;
        ctx.func = lookup_proc;
        ctx.dir = dir;
        ctx.flags = 0;
        ctx.buf = buf;
        ctx.priv_data = &ls;

        ls.name = name;
        ls.len = namelen;
        ls.inode = res_inode;
        ls.found = 0;

        ext2fs_process_dir_block(fs, &leaf_pblk, blockcnt, 0, 0, &ctx);
        if (ctx.errcode) {
            retval = ctx.errcode;
            goto cleanup;
        }
        if (ls.found) {
            break;
        }
        retval = htree_next_block(fs, dir, diri, &dx_info);
    } while (retval == 0);

cleanup:
    if (block_buf) {
        ext2fs_free_mem(&block_buf);
    }
    dx_release(&dx_info);

    return retval;
}

errcode_t ext2fs_lookup(ext2_filsys fs, ext2_ino_t dir, const char *name,
            int namelen, char *buf, ext2_ino_t *inode)
{
    errcode_t	retval;
    struct lookup_struct ls;
    struct ext2_inode diri;

    EXT2_CHECK_MAGIC(fs, EXT2_ET_MAGIC_EXT2FS_FILSYS);

    if ((retval = ext2fs_read_inode(fs, dir, &diri)) != 0)
        return retval;

    if (diri.i_flags & EXT2_INDEX_FL)
        return dx_namei(fs, dir, &diri, name, namelen, buf, inode);

    ls.name = name;
    ls.len = namelen;
    ls.inode = inode;
    ls.found = 0;

    retval = ext2fs_dir_iterate2(fs, dir, 0, buf, lookup_proc, &ls);
    if (retval)
        return retval;

    return (ls.found) ? 0 : EXT2_ET_FILE_NOT_FOUND;
}


