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
#include "wrapfs.h"

long wrapfs_decrypt(struct page  *source_page, struct page *dest_page, loff_t page_size, char *key);
long wrapfs_encrypt(struct page* source_page, struct page* dest_page, char *key, loff_t num_of_bytes_to_write );

int fill_zeroes(struct page* page, int index, loff_t pos, struct file* file, unsigned flags);

int wrapfs_writepage(struct page *page, struct writeback_control *wbc) {
   // printk("\nIn write page\n");
    int err = -EIO;
    struct inode *inode =NULL;
    struct inode *lower_inode;
    struct page *lower_page;
    struct address_space *lower_mapping; /* lower inode mapping */
    gfp_t mask;

#ifdef WRAPFS_CRYPTO
  //  char *encrypted_buffer;
    struct page *dest_page;
//    struct wrapfs_sb_info *sbi;
    long ret = 0;
#endif
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(inode->i_sb)->debug_address_space_ops,"Debug_wrapfs_writepage");
#endif
    
    inode = page->mapping->host;
    BUG_ON(!PageUptodate(page));	
    lower_inode = wrapfs_lower_inode(inode);

    if (!inode || !WRAPFS_I(inode) || !lower_inode) {
	err = 0;
	goto out;
    }

    lower_mapping = lower_inode->i_mapping;

    mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
    lower_page = find_or_create_page(lower_mapping, page->index, mask);
    if (!lower_page) {
        err = 0;
        set_page_dirty(page);
        goto out;
    }

    /* copy page data from our upper page to the lower page */
#ifdef WRAPFS_CRYPTO
   // printk("\n key ==> %s", WRAPFS_SB(inode->i_sb)->sb_key);
    
    if(NULL!= WRAPFS_SB(inode->i_sb)->sb_key) {
        dest_page = alloc_page(GFP_USER);
        if(dest_page == NULL) {
            printk ("alloc page for dest failed !!\n");
            goto out;
        }
        ret = wrapfs_encrypt(page,dest_page, WRAPFS_SB(inode->i_sb)->sb_key, PAGE_CACHE_SIZE );
        copy_highpage(lower_page, dest_page);
    }
    else {
       // printk("\n Encryption is enabled but key is NULL. Permission denied");
        //copy_highpage(lower_page, page);
	err = -EPERM;
	goto out_release;
    }
#else

    copy_highpage(lower_page, page);

#endif

    flush_dcache_page(lower_page);
    SetPageUptodate(lower_page);
    set_page_dirty(lower_page);


    if (wbc->for_reclaim) {
	unlock_page(lower_page);
	goto out_release;
    }

    BUG_ON(!lower_mapping->a_ops->writepage);
    wait_on_page_writeback(lower_page); 
    clear_page_dirty_for_io(lower_page);
    err = lower_mapping->a_ops->writepage(lower_page, wbc);

    if (err < 0)
	goto out_release;

    fsstack_copy_attr_atime(inode, lower_inode);

out_release:

#ifdef WRAPFS_CRYPTO
    __free_page(dest_page);
#endif
    page_cache_release(lower_page);
out:
    unlock_page(page);
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(inode->i_sb)->debug_address_space_ops,"err : %d", err);
#endif

    return err;
}



/* Readpage expects a locked page, and must unlock it */
int wrapfs_readpage(struct file *file, struct page *page) {
    //printk("\n call to read page\n");
    struct file *lower_file;
    struct inode *inode;
    mm_segment_t old_fs;
    char *page_data = NULL;
    mode_t orig_mode;
    long num_of_bytes =0;
    long err =0;

#ifdef WRAPFS_CRYPTO
    struct wrapfs_sb_info *sbi = NULL;    
    long err1 = 0;
    struct page * decrypt_page = NULL;
    char *decrypted_buf = NULL;

#endif
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_address_space_ops,"Debug_wrapfs_readpage");
#endif
    
    if (!WRAPFS_F(file)) {
	err = -ENOENT;
	goto out;
    }

    lower_file = wrapfs_lower_file(file);

    /* FIXME: is this assertion right here? */
    BUG_ON(lower_file == NULL);

    inode = file->f_path.dentry->d_inode;

    page_data = (char *) kmap(page);

    lower_file->f_pos = page_offset(page);
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    orig_mode = lower_file->f_mode;
    lower_file->f_mode |= FMODE_READ;
    num_of_bytes = vfs_read(lower_file, page_data, PAGE_CACHE_SIZE,
	    &lower_file->f_pos);
    lower_file->f_mode = orig_mode;
    set_fs(old_fs);

#ifdef WRAPFS_CRYPTO

    sbi = (struct wrapfs_sb_info*)file->f_path.dentry->d_sb->s_fs_info;
    if (NULL != sbi->sb_key) {

	decrypt_page = alloc_page(GFP_USER);
	if (decrypt_page == NULL) {
	    printk ("alloc page for dest failed !!\n");
	    goto out;
	}
	
	err1 = wrapfs_decrypt(page, decrypt_page,PAGE_CACHE_SIZE,sbi->sb_key);
	decrypted_buf = (char *)kmap(decrypt_page);

	if(err1 < 0) {
	    printk("\n key is set but decryption failed!!");
	//    kfree(decrypted_buf);
	    kunmap(decrypt_page);
	    kunmap(page);
	//    __free_page(decrypt_page);
	    err = -EINVAL;
	    goto out;
	}
	memcpy(page_data, decrypted_buf, PAGE_CACHE_SIZE);
    }
    else {
	printk("\n key is not set. User is not allowed to read file");
	err = -EPERM;
//	kunmap(decrypt_page);
	kunmap(page);
//	__free_page(decrypt_page);
	goto out; 
    }
#endif
    if(num_of_bytes >= 0)
	err = 0;
    else
	err = num_of_bytes;

    if (num_of_bytes >= 0 && num_of_bytes < PAGE_CACHE_SIZE)
	memset(page_data + num_of_bytes, 0, PAGE_CACHE_SIZE - num_of_bytes);
	
#ifdef WRAPFS_CRYPTO
        kunmap(decrypt_page);
  //      __free_page(decrypt_page);
#endif
	kunmap(page);
    	fsstack_copy_attr_atime(inode, lower_file->f_path.dentry->d_inode);
    	flush_dcache_page(page);

out:	if (err == 0)
	    SetPageUptodate(page);
    else
	ClearPageUptodate(page);

    unlock_page(page);

   // printk ("read_page: Returning %ld \n", err);
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_address_space_ops,"err : %ld", err);
#endif
    return err;

}


int wrapfs_read_lower_page_segment(struct page* page, int index, struct file* file, int *num_of_bytes)
{
    char *virt=NULL;
    loff_t offset=0;
    struct file *lower_file= NULL;
    mm_segment_t fs_save;
    int rc = 0;
    mode_t orig_mode;

    offset = ((((loff_t)index) << PAGE_CACHE_SHIFT) + 0);
    virt = kmap(page);

    if (!virt)
    {
	printk ("kmap failed !!\n");
    }    

    lower_file = wrapfs_lower_file(file);
    if (!lower_file)
	return -EIO;

    orig_mode = lower_file->f_mode;
    fs_save = get_fs();
    set_fs(get_ds());
    lower_file->f_mode |= FMODE_READ;
    rc = vfs_read(lower_file, virt, PAGE_CACHE_SIZE, &offset);
    lower_file->f_mode = orig_mode;
    set_fs(fs_save);
    if (rc >= 0) 
    {
        *num_of_bytes = rc;
        rc = 0;
    }     
    kunmap(page);
    flush_dcache_page(page);	

    return rc;
}


int wrapfs_write_begin(struct file *file, struct address_space *mapping,
                       loff_t pos, unsigned len, unsigned flags,
                       struct page **pagep, void **fsdata) {
    
    struct page *page;
    loff_t index;
    loff_t prev_page_end_size = 0;
    int rc = 0;
    int num_of_bytes = 0;
    //char *buf;
    //unsigned from = 0;
   // printk("\n *******pos in write begin*****: %lu", pos);
#ifdef WRAPFS_CRYPTO
    struct wrapfs_sb_info *sbi = NULL;
    long err1 = 0;
    struct page * decrypt_page = NULL;
    char *decrypted_buf = NULL;
    char *page_data = NULL;
    struct inode *cur_inode;
    loff_t cur_inode_end_offset, cur_inode_size;
    cur_inode = file->f_path.dentry->d_inode;
    cur_inode_size = cur_inode->i_size;
    cur_inode_end_offset = cur_inode_size & (PAGE_CACHE_SIZE - 1);
#endif
        
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_address_space_ops,"Debug_wrapfs_write_begin");
#endif
    index =(loff_t)(pos >> PAGE_CACHE_SHIFT);
  //  printk ("wrapfs_write_begin : index is : %lld\n", index);
    page = grab_cache_page_write_begin(mapping, index, flags);
    
    if (!page) {
        return -ENOMEM;
    }
   // printk("\n ****page_BEGIN****page index is %lld\n",page->index);
    
    *pagep = page;
    
    if (!PageUptodate(page)) {
        
        prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
        
#ifdef WRAPFS_CRYPTO
        if (prev_page_end_size >= i_size_read(page->mapping->host))  {
             zero_user(page, 0, PAGE_CACHE_SIZE);
            //rc = fill_zeroes(page, index, pos, file, flags);
        }
        else {
            sbi = (struct wrapfs_sb_info*)file->f_path.dentry->d_sb->s_fs_info;
            if (NULL != sbi->sb_key) {
                
                rc = wrapfs_read_lower_page_segment(page, index, file, &num_of_bytes);
                page_data = (char *) kmap(page);
                decrypt_page = alloc_page(GFP_USER);
                if (decrypt_page == NULL) {
                    printk ("alloc page for dest failed !!\n");
                    goto out;
                }
                //check for page_cache_size
                err1 = wrapfs_decrypt(page, decrypt_page,PAGE_CACHE_SIZE,sbi->sb_key);
                decrypted_buf = (char *)kmap(decrypt_page);
                            
                if(err1 < 0) {
                    printk("\n key is set but decryption failed!!");
                    kunmap(decrypt_page);
                    kunmap(page);
                    //    __free_page(decrypt_page);
                    rc = -EINVAL;
                    ClearPageUptodate(page);
                    goto out;
                }
                memcpy(page_data, decrypted_buf, PAGE_CACHE_SIZE);
            }
            else {
                printk("\n key is not set. User is not allowed to write to file");
                rc = -EPERM;
                goto out;
            }
        }
        
#else
        rc = wrapfs_read_lower_page_segment(page, index, file, &num_of_bytes);
        if (rc) {
            printk("Error attemping to read "
                   "lower page segment; rc = [%d]\n", rc);
            ClearPageUptodate(page);
            goto out;
        } else
            SetPageUptodate(page);
        if (prev_page_end_size >= i_size_read(page->mapping->host))  {
	   	 zero_user(page, 0, PAGE_CACHE_SIZE);
        }
        
#endif
    }

#ifdef WRAPFS_CRYPTO
    rc = fill_zeroes(page, index, pos, file, flags);
#endif
    if ((i_size_read(mapping->host) == prev_page_end_size) && (pos != 0)) {
	        zero_user(page, 0, PAGE_CACHE_SIZE);
	}

out:

    if (rc < 0) {
	unlock_page(page);
	page_cache_release(page);
    }
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_address_space_ops,"err : %d", rc);
#endif

    return rc;
}

int wrapfs_write_end(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned copied,
struct page *page, void *fsdata) {
    
    long err = 0;
    struct file *lower_file;
    mm_segment_t fs_seg;
    loff_t off_set;

    int is_append_set = 0;
    struct inode *inode = page->mapping->host;
    unsigned from = pos & (PAGE_CACHE_SIZE - 1);
   // unsigned to = from + copied;
    loff_t last_pos = 0;
    loff_t num_of_bytes_to_write =0;
    char *buf = NULL;
    int num_of_pages =0, page_index=0;

#ifdef WRAPFS_CRYPTO
    int ret = 0;
    struct wrapfs_sb_info *sbi;
    struct page *dest_page;
#endif
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_address_space_ops,"Debug_wrapfs_write_end");
#endif

    last_pos = pos + copied;

    /* zero the stale part of the page if we did a short copy */
    if (copied < len) {
	zero_user(page, from + copied, len - copied);
    }

    if (!PageUptodate(page))
	SetPageUptodate(page);
    /*
     * No need to use i_size_read() here, the i_size
     * cannot change under us because we hold the i_mutex.
     */

      if (last_pos > inode->i_size) {
        i_size_write(inode, last_pos);
    }
  
    off_set = (((loff_t)(page->index)<< PAGE_CACHE_SHIFT) + 0);

    page_index = (int)page->index;   	
 
    num_of_pages = (int)(inode->i_size / PAGE_SIZE) ;

    if ( page_index < ( num_of_pages)) {
	//num_of_bytes_to_write = PAGE_SIZE;
	num_of_bytes_to_write = copied;
    }
    else	
    { 	num_of_bytes_to_write = (int)(inode->i_size - off_set); 

    }
   
    lower_file = wrapfs_lower_file(file);

    if(!lower_file) {
	return -EIO;
    }

#ifdef WRAPFS_CRYPTO

    sbi = (struct wrapfs_sb_info*)(file->f_path.dentry->d_sb->s_fs_info);
	
    if(NULL != sbi->sb_key) {

	dest_page = alloc_page(GFP_USER);
	if (dest_page == NULL) {
	    printk ("alloc page failed in wrapfs_write_end !!\n");
	    goto cleanup;
	}
	ret = wrapfs_encrypt(page,dest_page, sbi->sb_key, num_of_bytes_to_write );
//	printk ("wrapfs_encrypt_page_segment is returning : %ld\n", ret);

	if (ret < 0) {
	    printk("Encrypt failed!!");
	    err = -EINVAL;
	    goto cleanup;
	}
    }
    else {

	printk("Data cannot be written and encrypted as key is null. Permission denied!!");
	err = -EPERM;
	goto cleanup;
    }
#endif
#ifdef WRAPFS_CRYPTO
    if(NULL != sbi->sb_key) {
        buf = kmap(dest_page);
        kunmap(dest_page);
    }
    else {
#endif
   
        buf = kmap(page);

#ifdef WRAPFS_CRYPTO
    }
#endif

   // printk("the buf content is %s \n", buf);
   // printk("value of offset is %lld", off_set);

    if (((lower_file->f_flags) & O_APPEND) == O_APPEND ) {
	lower_file->f_flags = lower_file->f_flags & ~O_APPEND;
	is_append_set = 1;
    }

    fs_seg = get_fs();
    set_fs(get_ds());
    err = vfs_write(lower_file, buf, num_of_bytes_to_write, &off_set );
    set_fs(fs_seg);
    mark_inode_dirty_sync(inode);


    if (is_append_set == 1) {
	lower_file->f_flags = (lower_file->f_flags & O_APPEND);
	is_append_set = 0;
    }

  //  printk("wrapfs_write_end : vfs write returned %ld \n ",err );

cleanup :       

    if(buf != NULL)
    {
        kunmap(page);
    }
    set_page_dirty(page);
    unlock_page(page);
    page_cache_release(page);
    if(err<0)
	copied = err;
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_address_space_ops,"copied : %ud", copied);
#endif
    
    return copied;
}

long wrapfs_decrypt(struct page  *source_page, struct page *dest_page, loff_t page_size, char *key) {
    
    struct crypto_blkcipher *tfm = NULL;
    struct blkcipher_desc desc;

    struct scatterlist src, dst;

    unsigned int ret = 0;
    printk("\n In wrapfs_decrypt \n");
    tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);

    if (IS_ERR(tfm)) {
	printk("failed to load transform Err123445 !!\n");
	ret = -EINVAL;
	goto out;
    }
    desc.tfm = tfm;
    desc.flags = 0;
    
    ret = crypto_blkcipher_setkey(tfm, key,strlen(key));
    if (ret) {
	printk("setkey() failed flags !!\n");
	ret = -EINVAL;
	goto out;
    }


    sg_init_table(&src, 1);
    sg_set_page(&src, source_page, page_size,0);
    sg_init_table(&dst, 1);
    sg_set_page(&dst, dest_page, page_size,0);

    ret = crypto_blkcipher_decrypt(&desc, &dst, &src, page_size);
   // printk ("Ret returned by crypto_blkcipher_encrypt is : %ld\n", ret);

    if (ret >= 0)
	ret = 0;

out:
    if (desc.tfm)
    {
	crypto_free_blkcipher(tfm);
	tfm = NULL;
    }

    return ret;

}

long wrapfs_encrypt(struct page* source_page, struct page* dest_page, char *key, loff_t num_of_bytes_to_write ) {
    
    struct crypto_blkcipher *tfm ;
    struct blkcipher_desc desc;

    struct scatterlist src, dst;

    unsigned int ret = 0;
    tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
	printk("failed to load transform Err123445 !!\n");
	ret = -EINVAL;
	goto out;
    }
    desc.tfm = tfm;
    desc.flags = 0;
    ret = crypto_blkcipher_setkey(desc.tfm, key,strlen(key));
    if (ret) {
        printk("setkey() failed flags !!\n");
        ret = -EINVAL;
        goto out;
    }

    sg_init_table(&src, 1);
    sg_set_page(&src, source_page, num_of_bytes_to_write,0);
    sg_init_table(&dst, 1);
    sg_set_page(&dst, dest_page, num_of_bytes_to_write,0);

    ret = crypto_blkcipher_encrypt(&desc, &dst, &src, num_of_bytes_to_write);
    //printk ("Ret returned by crypto_blkcipher_encrypt is : %ld\n", ret);

    if (ret >= 0)
	ret = 0;

out:
    if (desc.tfm)
    {
	crypto_free_blkcipher(tfm);
	tfm = NULL;
    }

    return ret;

}

int fill_zeroes(struct page* page, int index, loff_t pos, struct file* file, unsigned flags) {
  //  printk("\n @@@@@@@@@@@ in fill zeroes @@@@@@@@@");
    loff_t cur_inode_size;
    pgoff_t cur_inode_last_index;
    unsigned int cur_inode_end_offset;
    unsigned int zero_count;
    struct page *page_to_zeros = NULL;
    loff_t tempindex,ind;
    pgoff_t tempoffset;
    pgoff_t bytes_to_write;
    struct file *lower_file = wrapfs_lower_file(file);
    char *encrypted_buf = NULL;
    char *page_data_to_zeros = NULL;
    mm_segment_t old_fs;
    char * page_data = NULL;
    struct inode *lower_inode;
    unsigned int offset = 0;
    int err = 0, ret = 0;
    struct inode * cur_inode;
    struct page* dest_page;
    
    offset = pos & (PAGE_CACHE_SIZE - 1);
	//printk("\n in fill zeroes :: index : %lu, offset : %d\n", index, offset);
    
    cur_inode = file->f_path.dentry->d_inode;
	if (cur_inode)
        lower_inode = wrapfs_lower_inode(cur_inode);
    
    cur_inode_size = cur_inode->i_size;
    cur_inode_last_index = cur_inode_size >> (PAGE_CACHE_SHIFT);
    cur_inode_end_offset = cur_inode_size & (PAGE_CACHE_SIZE - 1);
    page_data = (char*)kmap(page);
    
    if (index == cur_inode_last_index) {
        if (pos > cur_inode_size) {
            //printk("Need to fill zeroes upto pos,* from cur_inode_size");
            zero_count = pos - cur_inode_size;
            memset(page_data + cur_inode_end_offset, 0, zero_count);
        }
        err =0;
    }
    else if (index > cur_inode_last_index) {
        
       //printk("\n ************* comming here ********************");
        
     	//memset(page_data, 0, offset);
        tempoffset = cur_inode_end_offset;
        tempindex = cur_inode_last_index;
        
        while (tempindex < index) {
            page_to_zeros = grab_cache_page_write_begin(cur_inode->i_mapping,
                                                        tempindex, flags);
            lower_file->f_pos = cur_inode_size;
            
            ind = tempindex<<PAGE_CACHE_SHIFT;
            
            if (page_to_zeros == NULL) {
                printk("grab_cache_page failed!!");
                kfree(encrypted_buf);
                err = -ENOMEM;
                goto out_holes;
            }
            dest_page = alloc_page(GFP_USER);
            if (dest_page == NULL) {
                printk ("alloc page failed in fill_zeroes !!\n");
                goto out_holes;
            }
            page_data_to_zeros = (char *)kmap(page_to_zeros);
            bytes_to_write = PAGE_CACHE_SIZE - tempoffset;
            memset(page_data_to_zeros+tempoffset, 0,bytes_to_write);
            
            ret = wrapfs_encrypt(page_to_zeros, dest_page, WRAPFS_SB(file->f_dentry->d_sb)->sb_key, PAGE_CACHE_SIZE);
            if (ret < 0) {
                printk("Encrypt failed!!");
                err = -EINVAL;
                goto free_holes;;
            }
            
           // flush_dcache_page(page_to_zeros);
            encrypted_buf = kmap(dest_page);
            
            old_fs = get_fs();
            set_fs(KERNEL_DS);
            err = vfs_write(lower_file, encrypted_buf,bytes_to_write, &ind);
            set_fs(old_fs);
            
        free_holes:
	        kunmap(dest_page);
            kunmap(page_to_zeros);
            unlock_page(page_to_zeros);
            page_cache_release(page_to_zeros);
            if (err < 0) {
                kfree(encrypted_buf);
                goto out_holes;
            }
            err = 0;
            mark_inode_dirty_sync(cur_inode);
            tempoffset = 0;
            tempindex = tempindex+1;
        } 
    out_holes:
        if ((err < 0) && (page_to_zeros != NULL))
            ClearPageUptodate(page_to_zeros);
    }
    return err;
}

sector_t wrapfs_bmap(struct address_space *mapping, sector_t block) {
    int rc = 0;
    struct inode *inode=NULL;
    struct inode *lower_inode;
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(inode->i_sb)->debug_address_space_ops,"Debug_wrapfs_bmap");
#endif
    inode = (struct inode *)mapping->host;
    lower_inode = wrapfs_lower_inode(inode);
    if (lower_inode->i_mapping->a_ops->bmap)
        rc = lower_inode->i_mapping->a_ops->bmap(lower_inode->i_mapping,
                                                 block);
    
#ifdef EXTRA_CREDIT_1
	debug_address_ops(WRAPFS_SB(inode->i_sb)->debug_address_space_ops,"err : %d", rc);
#endif
    return rc;
}

int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    int err;
    struct file *file, *lower_file;
    const struct vm_operations_struct *lower_vm_ops;
    struct vm_area_struct lower_vma;
    
#ifdef EXTRA_CREDIT_1
	debug_all_other_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_all_other_ops,"Debug_wrapfs_fault");
#endif
    
    memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
    file = lower_vma.vm_file;
    lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
    BUG_ON(!lower_vm_ops);

    lower_file = wrapfs_lower_file(file);
    /*
     * XXX: vm_ops->fault may be called in parallel.  Because we have to
     * resort to temporarily changing the vma->vm_file to point to the
     * lower file, a concurrent invocation of wrapfs_fault could see a
     * different value.  In this workaround, we keep a different copy of
     * the vma structure in our stack, so we never expose a different
     * value of the vma->vm_file called to us, even temporarily.  A
     * better fix would be to change the calling semantics of ->fault to
     * take an explicit file pointer.
     */
    lower_vma.vm_file = lower_file;
    err = lower_vm_ops->fault(&lower_vma, vmf);
#ifdef EXTRA_CREDIT_1
	debug_all_other_ops(WRAPFS_SB(file->f_dentry->d_sb)->debug_all_other_ops,"err : %d", err);
#endif
    return err;
}


/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */

const struct address_space_operations wrapfs_aops = {
    /* empty on purpose */
};

const struct vm_operations_struct wrapfs_vm_ops = {
    .fault		= wrapfs_fault,
};


const struct address_space_operations wrapfs_mmap_aops = {
    .writepage   = wrapfs_writepage,
    .readpage    = wrapfs_readpage,
    .write_begin = wrapfs_write_begin,
    .write_end   = wrapfs_write_end,
    .bmap = wrapfs_bmap,
};


