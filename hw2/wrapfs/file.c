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

static ssize_t wrapfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);

	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err, ret = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if(err>0){
	    ret = wrapfs_set_dflag(dentry->d_inode , 1);

	}
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}

	return err;
}

static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
	err = vfs_readdir(lower_file, filldir, dirent);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = wrapfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "wrapfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!WRAPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &wrapfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &wrapfs_aops; /* set our aops */
	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int wrapfs_open(struct inode *inode, struct file *file)
{
    int err = 0, ret;
    struct file *lower_file = NULL;
    struct path lower_path;
    char * checksum_calculated = NULL;
    char * checksum_from_EA = NULL;
    char * value = NULL;
    char * CHECKSUM_TYPE = "md5";
    char * HAS_INTEGRITY = "user.has_integrity";
    char * INTEGRITY_VALUE = "user.integrity_val";
    int diglength = 16;
    value = kmalloc(1,GFP_KERNEL);
    if(value == NULL) { 
	printk("\nNo memory to allocate.\n");
	err = -ENOMEM;
	goto out_err;
    }
    memset(value,0,1);
    checksum_from_EA = kmalloc(2*diglength +1,GFP_KERNEL);
    if(checksum_from_EA == NULL) {  
	printk("Memory cannot be allocated");
	err = -ENOMEM;
	goto out_err;
    }
    memset(checksum_from_EA, 0, 2*diglength +1);
    //don't open unhashed/deleted files 

    checksum_calculated = kmalloc(2*diglength +1 , GFP_KERNEL);
    if(checksum_calculated == NULL) {  
	printk("Memory cannot be allocated in wrapfs_open");
	err = -ENOMEM;
	goto out_err;
    }
    memset(checksum_calculated, 0, 2*diglength +1);

    /* don't open unhashed/deleted files */
    if (d_unhashed(file->f_path.dentry)) {
	err = -ENOENT;
	goto out_err;
    }

    file->private_data =
	kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
    if (!WRAPFS_F(file)) {
	err = -ENOMEM;
	goto out_err;
    }

    /* open lower object and link wrapfs's file struct to lower's */
    wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
    lower_file = dentry_open(lower_path.dentry, lower_path.mnt, file->f_flags, current_cred());
    if (IS_ERR(lower_file)) {
	err = PTR_ERR(lower_file);
	lower_file = wrapfs_lower_file(file);
	if (lower_file) {
	    wrapfs_set_lower_file(file, NULL);
	    fput(lower_file); /* fput calls dput for lower_dentry */
	}
    } else {
	wrapfs_set_lower_file(file, lower_file);
    }

    if (err)
	goto out_err;
    else
    {
	if(S_ISDIR(lower_path.dentry->d_inode->i_mode)) {  
	    fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
	    goto out_err;
	}
	else if(S_ISREG(lower_path.dentry->d_inode->i_mode)) {
	    //check if has_integrity EA exists for the file. If it exists and value =1, compare the checksums
	    ret = vfs_getxattr(lower_path.dentry, HAS_INTEGRITY, value, (size_t)1);
	    if(ret == 1 && value[0] == '1')
	    {
		ret = vfs_getxattr(lower_path.dentry, INTEGRITY_VALUE , checksum_from_EA, 2*diglength +1);
		if(ret <= 0 || ret!=2*diglength) {
		    printk("Invalid checksum value. Either checksum is not set or file is corrupted\n");
		    err = -EPERM;
		    goto out_err;
		}	
		else if (ret == 2*diglength) { 	
		    ret = wrapfs_compute_checksum(lower_file, checksum_calculated,CHECKSUM_TYPE);
		}
		if(ret !=0) {
		    printk("failure in computing the checksum \n");
		    err =-EPERM;
		    goto out_err;
		}
		//compare the checksums from both the values.
		ret= strcmp(checksum_calculated,checksum_from_EA);
		if(ret!=0) {
		    if(wrapfs_get_dflag(lower_path.dentry->d_inode)) {	
			err = vfs_setxattr(lower_path.dentry, INTEGRITY_VALUE, checksum_calculated, 2*diglength, XATTR_REPLACE);
			printk("Checksum successfully updated before opening a file as another process seems to write on this file.");
		    }
		    else {
			printk("\nUnable to open the file. Checksum does not match\n");
			err = -EPERM;
			goto out_err;
		    }
		}
		printk("checksum matched. File opened \n");
	    }
	    }
	   fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
	}

out_err:
	if(err) {
	    lower_file = wrapfs_lower_file(file);
	    if (lower_file) {
		wrapfs_set_lower_file(file, NULL);
		fput(lower_file); /* fput calls dput for lower_dentry */
	    }
	    kfree(WRAPFS_F(file));
	}
	if(value != NULL)
	    kfree(value);
	if(checksum_from_EA != NULL)
	    kfree(checksum_from_EA);
	if(checksum_calculated !=NULL)
	    kfree(checksum_calculated);
	return err;
    }
static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

	return err;
}
/* release all lower object references & free the file info structure */

static int wrapfs_file_release(struct inode *inode, struct file *file)
{
    struct file *lower_file; 

    struct dentry *lower_dentry;
    struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
    int err,ret = 0;
    char* checksum_val = NULL;
    char* value = NULL;
    char* checksum_type = "md5";
    char* has_integrity = "user.has_integrity";
    char* integrity_val = "user.integrity_val";
    int diglength = 16;
    struct dentry* dentry= NULL;
    dentry = file->f_path.dentry;
    wrapfs_get_lower_path(dentry,&lower_path);
    lower_dentry = lower_path.dentry;
    lower_file = wrapfs_lower_file(file);
    
    checksum_val = kmalloc(2*diglength +1,GFP_KERNEL);
    if(checksum_val == NULL) {
	printk("Memory allocation failed \n");
	err = -ENOMEM;
	goto close_file;
    }
    memset(checksum_val, 0, 2*diglength +1);

    value = kmalloc(1,GFP_KERNEL);
    if(value == NULL) {
	printk("\nMemory allocation failed\n");
	err = -ENOMEM;
	goto close_file;
    }
    memset(value, 0,1);
    if (lower_file) {
	if(S_ISDIR(lower_path.dentry->d_inode->i_mode))
	    goto close_file;
	if(wrapfs_get_dflag(dentry->d_inode)) {    
	    lower_parent_dentry = lock_parent(lower_dentry);
	    ret = vfs_getxattr(lower_path.dentry, has_integrity, value,(size_t)1);
	    if(ret == 1 && value[0] == '1') {
		ret = wrapfs_compute_checksum(lower_file,checksum_val,checksum_type);	
		if(ret !=0) {  
		    printk("\n error while computing the checksum of the file\n");
		    err = -EPERM;
		    goto close_file;
		}
		err = vfs_setxattr(lower_path.dentry, integrity_val,checksum_val,2*diglength,XATTR_REPLACE);
		printk("Checksum successfully updated before closing the file.");	
	    }
	}
	wrapfs_set_dflag(dentry->d_inode , 0);
    }

close_file: 
    if (lower_parent_dentry)
	unlock_dir (lower_parent_dentry);
    if(value)
	kfree(value);
    if(checksum_val)
	kfree(checksum_val);
    wrapfs_set_lower_file(file, NULL);
    fput(lower_file);
    kfree(WRAPFS_F(file));
    return 0;
}
static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
