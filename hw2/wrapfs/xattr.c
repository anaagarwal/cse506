
#include "wrapfs.h"
#include "xattr.h"
#include <linux/cred.h>

 /* sets extended attribute*/
int wrapfs_setxattr(struct dentry *dentry, const char *name,
	const void *value, size_t size, int flags)
{

    int err = 0;
    int ret = 0;
    struct dentry *lower_dentry = NULL;
    struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
    struct file * lower_file = NULL;
    char *checksum_val = NULL;
    char* str = (char *)value;
    if(value == NULL){
	printk("Invalid argument");
	return -EINVAL;
    }

    if(!strcmp(name,integrity_val_EA)) {
	printk("User does not have permissions to set this attribute");
	return -EACCES;
    }

    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;
    lower_parent_dentry = lock_parent(lower_dentry);

    if(!strcmp(name,has_integrity_EA)) {
	//check for integrity_type and accordingly set values for algortihm type and sizes
	if(!current_uid()) {
	    if (S_ISDIR(lower_dentry->d_inode->i_mode)) {
		 if(str[0]=='1' ||  str[0]=='1') {
		printk ("Integrity value does not implies to directories.Only setting has_integrity !\n");
		}
		else {
		    printk("Invalid argument for has_integrity");
		    err = - EINVAL;
		}
		goto out;
	    }
	    else if (S_ISREG(lower_dentry->d_inode->i_mode)) {
		checksum_val = kmalloc(MD5_CHECKSUM_VAL , GFP_KERNEL);
		memset(checksum_val, 0, MD5_CHECKSUM_VAL);
		if(str[0]=='1') {
		    lower_file = dentry_open(lower_path.dentry, lower_path.mnt, flags, current_cred());
		    err = wrapfs_compute_checksum(lower_file, (char *)checksum_val, checksum_algorithm);
		    if(checksum_val==NULL) {
			printk("checksum value is null. cannot compute checksum");
			err = -ENODATA;
			goto out;
		    }
		    err = vfs_setxattr(lower_dentry, integrity_val_EA, checksum_val, 32, flags);
		}
		else if(str[0]=='0') {
		    ret= vfs_getxattr(lower_dentry, integrity_val_EA, checksum_val, MD5_CHECKSUM_VAL);
		    if(ret == MD5_CHECKSUM_VAL-1){
			err= vfs_removexattr(lower_dentry, integrity_val_EA);
		    }
		    else {
			err = ret;
		    }
		}
		else {
		    printk("Invalid argument for has_integrity");
		    err = - EINVAL;
		    goto out;
		}
	    }
	    else {
		printk("operation is not supported for this file type");
		err = - EPERM;
		goto out;
	    }	 
	}
	else {	
	    printk("operation is not supported for this user");
	    err = - EPERM;
	    goto out;
	}
    }
out:
    if(!err) {
	err = vfs_setxattr(lower_dentry, (char *)name, value, size, flags);
    }
    wrapfs_put_lower_path(dentry, &lower_path);
    unlock_dir(lower_parent_dentry);
    if(checksum_val)
	kfree(checksum_val);
    if(lower_file)
	fput(lower_file);
    return err;
}

/* Gets extended attribute*/
ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, const void *value, size_t size)
{
    int err = 0;
    struct dentry *lower_dentry = NULL;
    struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;
    lower_parent_dentry = lock_parent(lower_dentry);

    err = vfs_getxattr(lower_dentry, (char *) name, (void*) value, size);
    if(err<0){
	err = -ENODATA;
    }
    unlock_dir(lower_parent_dentry);
    wrapfs_put_lower_path(dentry, &lower_path);
    return err;
}
/* Remove extended attribute*/
int wrapfs_removexattr(struct dentry *dentry, const char *name) {
    int err = 0;
    int ret = 0;
    char * value = NULL;
    struct dentry *lower_dentry;
    struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
   
    if(!(strcmp(name, integrity_val_EA))) {
	printk("Integrity value deletion is not permitted");
	return -EOPNOTSUPP;
    }
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;
    lower_parent_dentry = lock_parent(lower_dentry);

    if(!(strcmp(name, has_integrity_EA))) {
	if(!current_uid()) {
	    value = kmalloc(1, GFP_KERNEL);
	    if (S_ISREG(lower_dentry->d_inode->i_mode)) {
		ret = vfs_getxattr(lower_dentry, (char *) name, (void*) value, (size_t)1);
		if(ret <0) {
		    err = -ENODATA;
		    goto out;
		}
		if(ret == 1 && value[0] == '1') {
		    ret = vfs_removexattr(lower_dentry, integrity_val_EA);
		    printk ("Integrity value removed.\n");
		}
	    }
	    else if(S_ISDIR(lower_dentry->d_inode->i_mode)) {
		printk ("Only has_integrity removed for the directory\n");
		goto out;
	    }
	    else {
		printk ("Not a regular file. Integrity does not exist \n");
		err = -EINVAL;
		goto out;
	    }
	}	
	else {
	    printk ("Operation is not supported for this user !\n");
	    err = -EPERM;	
	    goto out;
	}
    }
    if(!err)
	err= vfs_removexattr(lower_dentry, (char *) name);
out:
    if(value)
	kfree(value);
    unlock_dir(lower_parent_dentry);
    //wrapfs_put_lower_path(dentry, &lower_path);
    printk("successfully removed attribute");
    return err;
}

 /* List extended attribute*/
ssize_t wrapfs_listxattr(struct dentry *dentry, char *list, size_t size) {
    int err = 0;
    struct dentry *lower_dentry;
    struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
    char *extended_list = NULL;
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;
    lower_parent_dentry = lock_parent(lower_dentry);
    extended_list = list;
    err= vfs_listxattr(lower_dentry, extended_list, size);
    if(err < 0) {
    	err = -ENODATA;
    }
   // printk("wrapfs_listxattr after syscall %d \n" , err);
    unlock_dir(lower_parent_dentry);
    wrapfs_put_lower_path(dentry, &lower_path);
    return err;
}

