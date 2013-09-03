/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _WRAPFS_H_
#define _WRAPFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/page-flags.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <asm/ioctl.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/limits.h>

/* These three statements are used to enable and disbale  
 * the extra credit and encryption decryption
 *  START
 */
 
#define EXTRA_CREDIT_1
//#define EXTRA_CREDIT_2
#define WRAPFS_CRYPTO

/*End*/
	 
/* These struct are defined for the wrapfs_parse_option function 
 * defined in main.c .enum is made to incorporate the two tokens, 
 * 	debug and mmap options.
 *  START
 */
 
struct match_token {
  int token;
  const char *pattern;
};

typedef struct match_token match_table_t[];

enum {MAX_OPT_ARGS = 3};
  
/* Describe the location within a string of a substring */
typedef struct {
  char *from;
  char *to;
} substring_t;

int match_token(char *, const match_table_t table, substring_t args[]);
int match_int(substring_t *, int *result);

enum {
  Opt_debug,
  Opt_mmap,
};

static const match_table_t wrapfs_tokens = {
  {Opt_debug, "debug=%u"},
  {Opt_mmap, "mmap"},
};

/* END */

/*
 * Necessary function required for blowfish algortihm as taken from 
 * FISTGEN source code.
 */ 
#ifdef EXTRA_CREDIT_2
 
#define BF_ENC(LL,R,S,P)				\
  {							\
    BF_LONG t,u,v;					\
    u=R>>BF_0;						\
    v=R>>BF_1;						\
    u&=BF_M;						\
    v&=BF_M;						\
    t=  *(BF_LONG *)((unsigned char *)&(S[  0])+u);	\
    u=R>>BF_2;						\
    t+= *(BF_LONG *)((unsigned char *)&(S[256])+v);	\
    v=R<<BF_3;						\
    u&=BF_M;						\
    v&=BF_M;						\
    t^= *(BF_LONG *)((unsigned char *)&(S[512])+u);	\
    LL^=P;						\
    t+= *(BF_LONG *)((unsigned char *)&(S[768])+v);	\
    LL^=t;						\
  }
#define BF_LONG unsigned long
#define BF_ROUNDS       16
#define BF_BLOCK        8

#define BF_M    0x3fc
#define BF_0    22L
#define BF_1    14L
#define BF_2     6L
#define BF_3     2L 


typedef struct bf_key_st {
  BF_LONG P[BF_ROUNDS + 2];
  BF_LONG S[4 * 256];
} BF_KEY;
  
extern BF_KEY key;

#define BF_ENCRYPT      1
#define BF_DECRYPT      0
  
/* If you make this 'unsigned int' the pointer variants will work on
 * the Alpha, otherwise they will not.  Strangly using the '8 byte'
 * BF_LONG and the default 'non-pointer' inner loop is the best configuration
 * for the Alpha */
  
#define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24L,	\
			 l|=((unsigned long)(*((c)++)))<<16L,	\
			 l|=((unsigned long)(*((c)++)))<< 8L,	\
			 l|=((unsigned long)(*((c)++))))
 

#define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff),	\
			 *((c)++)=(unsigned char)(((l)     )&0xff))
 

extern void BF_encrypt(BF_LONG *data,BF_KEY *key,int encrypt);
extern void BF_cfb64_encrypt(unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec,  int *num, int encrypt);
extern int wrapfs_encode_filename(const char *,int,char *,char *);
extern int wrapfs_decode_filename(const char *name,int length,char *key);

#endif

/* the file system name */
#define WRAPFS_NAME "wrapfs"

/* wrapfs root inode number */
#define WRAPFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)


/* These are the custome enabled printk statements which are made using the normal 
 * UDBG printk as stated to be done. defining the custom based printk was seen from
 * ecryptfs code.
 */
 
#ifdef EXTRA_CREDIT_1

#define debug_super_block_ops(flag, fmt, arg...)		\
  flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n",		\
		__FILE__, __func__, __LINE__, ## arg) : 1;
		
#define debug_inode_ops(flag, fmt, arg...)			\
  flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n",		\
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define debug_dentry_ops(flag, fmt, arg...)			\
  flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n",		\
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define debug_file_ops(flag, fmt, arg...)			\
  flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n",		\
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define debug_address_ops(flag, fmt, arg...)			\
  flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n",		\
		__FILE__, __func__, __LINE__, ## arg) : 1;
		
#define debug_all_other_ops(flag, fmt, arg...)			\
  flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n",		\
		__FILE__, __func__, __LINE__, ## arg) : 1;
		
#endif

//Newly added
#define WRAPFS_MAGIC 's'
#define WRAPFS_IOCSETD  _IOW(WRAPFS_MAGIC, 2 , char *)
#define MD5_SIGNATURE_SIZE 16


/* operations vectors defined in specific files */
extern const struct file_operations wrapfs_main_fops;
extern const struct file_operations wrapfs_dir_fops;
extern const struct file_operations wrapfs_main_mmap_fops;

extern const struct inode_operations wrapfs_main_iops;
extern const struct inode_operations wrapfs_dir_iops;
extern const struct inode_operations wrapfs_symlink_iops;
extern const struct super_operations wrapfs_sops;
extern const struct dentry_operations wrapfs_dops;
extern const struct address_space_operations wrapfs_aops, wrapfs_dummy_aops;
extern const struct address_space_operations wrapfs_mmap_aops;
extern const struct vm_operations_struct wrapfs_vm_ops;

extern int wrapfs_init_inode_cache(void);
extern void wrapfs_destroy_inode_cache(void);
extern int wrapfs_init_dentry_cache(void);
extern void wrapfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern int wrapfs_writepage(struct page *page, struct writeback_control *wbc);

extern int wrapfs_write_begin(struct file *file, struct address_space *mapping,
			      loff_t pos, unsigned len, unsigned flags,
			      struct page **pagep, void **fsdata);

extern int wrapfs_write_end(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned copied,
			    struct page *page, void *fsdata);
extern int wrapfs_readpage(struct file *file, struct page *page);	
extern sector_t wrapfs_bmap(struct address_space *mapping, sector_t block);				   
extern struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd);
extern struct inode *wrapfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

/* Newly added
 * New function defination added which are defined in main.c
 * checksum is defined in file computeKey.c.
 */
int wrapfs_parse_options(char *);
void set_enable_debug(unsigned long);
void set_disable_debug(void);
int checksum(char *user_key, char *chksum);

/* file private data */
struct wrapfs_file_info {
  struct file *lower_file;
  const struct vm_operations_struct *lower_vm_ops;
};

/* wrapfs inode data in memory */
struct wrapfs_inode_info {
  struct inode *lower_inode;
  struct inode vfs_inode;
};

/* wrapfs dentry data in memory */
struct wrapfs_dentry_info {
  spinlock_t lock;	/* protects lower_path */
  struct path lower_path;
};

/* wrapfs super-block data in memory */
struct wrapfs_sb_info {

  struct super_block *lower_sb;
  int mmap_option_set;
  unsigned char *sb_key;
	
  /*
   * Flags for debug declared in super block 
   */	
#ifdef EXTRA_CREDIT_1
  int debug_super_block_ops;
  int debug_inode_ops;
  int debug_dentry_ops;
  int debug_file_ops;
  int debug_address_space_ops;
  int debug_all_other_ops;
#endif
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * wrapfs_inode_info structure, WRAPFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct wrapfs_inode_info *WRAPFS_I(const struct inode *inode)
{
  return container_of(inode, struct wrapfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define WRAPFS_D(dent) ((struct wrapfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define WRAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define WRAPFS_F(file) ((struct wrapfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *wrapfs_lower_file(const struct file *f)
{
  return WRAPFS_F(f)->lower_file;
}

static inline void wrapfs_set_lower_file(struct file *f, struct file *val)
{
  WRAPFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *wrapfs_lower_inode(const struct inode *i)
{
  return WRAPFS_I(i)->lower_inode;
}

static inline void wrapfs_set_lower_inode(struct inode *i, struct inode *val)
{
  WRAPFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *wrapfs_lower_super(
						     const struct super_block *sb)
{
  return WRAPFS_SB(sb)->lower_sb;
}

static inline void wrapfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
  WRAPFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
  dst->dentry = src->dentry;
  dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void wrapfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
  spin_lock(&WRAPFS_D(dent)->lock);
  pathcpy(lower_path, &WRAPFS_D(dent)->lower_path);
  path_get(lower_path);
  spin_unlock(&WRAPFS_D(dent)->lock);
  return;
}
static inline void wrapfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
  path_put(lower_path);
  return;
}
static inline void wrapfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
  spin_lock(&WRAPFS_D(dent)->lock);
  pathcpy(&WRAPFS_D(dent)->lower_path, lower_path);
  spin_unlock(&WRAPFS_D(dent)->lock);
  return;
}
static inline void wrapfs_reset_lower_path(const struct dentry *dent)
{
  spin_lock(&WRAPFS_D(dent)->lock);
  WRAPFS_D(dent)->lower_path.dentry = NULL;
  WRAPFS_D(dent)->lower_path.mnt = NULL;
  spin_unlock(&WRAPFS_D(dent)->lock);
  return;
}
static inline void wrapfs_put_reset_lower_path(const struct dentry *dent)
{
  struct path lower_path;
  spin_lock(&WRAPFS_D(dent)->lock);
  pathcpy(&lower_path, &WRAPFS_D(dent)->lower_path);
  WRAPFS_D(dent)->lower_path.dentry = NULL;
  WRAPFS_D(dent)->lower_path.mnt = NULL;
  spin_unlock(&WRAPFS_D(dent)->lock);
  path_put(&lower_path);
  return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
  struct dentry *dir = dget_parent(dentry);
  mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
  return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
  mutex_unlock(&dir->d_inode->i_mutex);
  dput(dir);
}
#endif	/* not _WRAPFS_H_ */
