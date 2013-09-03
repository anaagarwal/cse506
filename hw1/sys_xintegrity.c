
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include<linux/fs.h>
#include<linux/buffer_head.h>
#include<linux/err.h>
#include<linux/crypto.h>
#include<linux/scatterlist.h>
#include <linux/linkage.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <asm/uaccess.h>

#include "syscall_xintegrity.h"
int get_integrity_xattr(struct file * filp, char * xattribute, char * digest, int digestlen);

int crypt_init_desc(struct hash_desc *desc);
asmlinkage extern long (*sysptr)(void *arg);
asmlinkage long xintegrity(void *arg)
{
    int rc = 0;
    int ret,fd = 0;
    unsigned char flag;
    char *file_name;
    if (arg == NULL)
    {
	return -EINVAL;
    } else {
	ret = copy_from_user(&flag, arg, sizeof(char));
	if(ret) {
	    printk("\n Flag copy from user failed.");
	    return -EFAULT;
	}
	switch(flag){
	    case '1':
		rc = get_existing_integrity(arg);
		if(rc){
		    printk("\ncompute_and_set_integrity failed. rc = %d", rc);
		    return rc;
		}

		break;
	    case '2':
		//compute integrity
		rc = compute_updated_integrity(arg);
		if(rc){
		    printk("\ncompute_updated_integrity failed. rc = %d", rc);
		    return rc;
		}
		break;
	    case '3':
		//open with check integrity
		file_name = (char *)kmalloc(FILE_NAME_SIZE, GFP_KERNEL);
		if(file_name){
		    rc= open_file_check_integrity(arg,file_name);
		    if(rc){
			printk("\n Cannot return file descriptor. Compute_updated_integrity failed. rc = %d", rc);
			return rc;
		    }
		    else{
			fd = get_fd(file_name);
			kfree(file_name);
			file_name = NULL;
			if(fd)
			    rc=fd;
			else
			    return -EPERM;
		    }
		}
		else {
		    printk("\n sys_xintegrity: kmalloc failed for %d bytes", FILE_NAME_SIZE);
		    return -ENOMEM;
		}

		break;
	    default:
		printk("Returning default case");
	}
	return rc;
    }
}
//Mode1
int get_existing_integrity(void *arg)
{

    struct mode1 *argsptr= NULL;
    struct file *filp = NULL;
    struct inode *node = NULL;
    char *filename = NULL;
    int ret,dgst,diglength;
    int j =0;
    int count =0;
    char digest[CHECKSUM_BUFFER_SIZE];
    mm_segment_t oldfs = get_fs();
    //    char inode_xattr_value[16];

    memset(digest, 0, CHECKSUM_BUFFER_SIZE);

    argsptr =(struct mode1 *)kmalloc(sizeof(struct mode1),GFP_KERNEL);
    if(argsptr==NULL){
	return -ENOMEM;
    }
    memset((void *)argsptr, 0, sizeof(struct mode1));
    ret = copy_from_user(argsptr,arg,sizeof(struct mode1));
    if(ret) {
	printk("\n Copy From User failed.");
	kfree(argsptr);
	return -EFAULT;
    }
    filename = getname(argsptr->filename);
    if(filename==NULL){
	printk("\nget_exisiting_integrity: getname failed while retrieving filename)");
	kfree(argsptr);
	return -ENOENT;
    }
    filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
	printk("Read File Error. No such file exists %d\n", (int) PTR_ERR(filp));
	putname(filename);
	kfree(argsptr);
	return -ENOENT;
    }
    if (!filp->f_op->read){
	printk("User does not have permission to read file %d\n", (int) PTR_ERR(filp));
	return -EACCES; // User denied read access
    }
    if(filp) {
	node = filp->f_mapping->host;
	if(node->i_op->getxattr) {
	    node->i_op->getxattr(filp->f_dentry,  inode_xattr_value , (void *)digest, CHECKSUM_BUFFER_SIZE);
	    for(j=0; j < 16 /*mode_2_value->ilen*/; ++j) {
		//printk("%02x", digest[j] & 0xFF);
		if(digest[j]==0){
		    count++;
		}
	    }
	    if(count==16){
		printk("File Integrity does not exist for file %s", filename);
		ret =1;
		//return 1;
	    }
	    else{
		printk("File Integrity exist for file %s", filename);
	    }

	    dgst = copy_to_user(argsptr->ibuf, digest, CHECKSUM_BUFFER_SIZE);
	    argsptr->ilen = CHECKSUM_BUFFER_SIZE;
	    diglength = copy_to_user(arg, argsptr, sizeof(struct mode1));


	} else {
	    printk("\nstore_hash_xattr: extended attributes not supported");
	    filp_close(filp,NULL);
	    putname(filename);
	    kfree(argsptr);
	    return -EPERM;
	}
    } else {
	printk("\nstore_hash_xattr: file pointer is NULL. check if file is open");
	filp_close(filp,NULL);
	putname(filename);
	kfree(argsptr);
	return -ENOENT;
    }
    set_fs(oldfs);
    filp_close(filp,NULL);

    putname(filename);
    kfree(argsptr);
    return ret;

}



//Mode2
int compute_updated_integrity(void *arg)
{
    struct mode2 *argsptr= NULL;
    char *filename = NULL;
    char *credbuf= NULL;
    int pwdMatch, ret,rc = 0;
    char * buf = NULL;
    char digest[CHECKSUM_BUFFER_SIZE];
    int flag =2;
    argsptr =(struct mode2 *)kmalloc(sizeof(struct mode2),GFP_KERNEL);
    if(argsptr==NULL){
	return -ENOMEM;
    }
    memset((void *)argsptr, 0, sizeof(struct mode2));
    ret = copy_from_user(argsptr,arg,sizeof(struct mode2));
    if(ret) {
	printk("\n Copy From User failed.");
	kfree(argsptr);
	return -EFAULT;
    }
    filename = getname(argsptr->filename);
    credbuf = getname(argsptr->credbuf);
    if(filename==NULL || credbuf==NULL){
	printk("\ncompute_updated_integrity: getname failed while retrieving mandatory information(password OR filename)");
	if(credbuf != NULL)
	    putname(credbuf);
	if(filename != NULL)
	    putname(filename);
	kfree(argsptr);
	return -ENOENT;
    }
    //validate password
    pwdMatch = validate_password(credbuf, argsptr->clen);
    if(pwdMatch==1){
	buf = kmalloc(FILE_CHUNK_SIZE, GFP_KERNEL);
	if(buf==NULL){
	   putname(filename);
	   kfree(argsptr);
	   return -ENOMEM;
	}
	ret = read_file_checksum(argsptr->filename, buf,digest, FILE_CHUNK_SIZE,flag);
	rc  = copy_to_user(argsptr->ibuf,digest,CHECKSUM_BUFFER_SIZE);
	argsptr->ilen = CHECKSUM_BUFFER_SIZE;
	rc  = copy_to_user(arg, argsptr, sizeof(struct mode2));

	kfree(buf);
    }
    else{
	printk("Invalid/Wrong password");
	putname(credbuf);
	putname(filename);
	kfree(argsptr);
	return -EACCES;
    }
    //set values in variable to be fetched at user end.
    putname(credbuf);
    putname(filename);
    kfree(argsptr);
    return ret;
}

//Read file and calculate checksum
int read_file_checksum(const char *filename, char *buf, char *digest, int len,int flag)
{
    struct file *filp;
    struct scatterlist sg[1];
    struct hash_desc desc;
    mm_segment_t oldfs;
    int bytes, rc,j,count =0;
    int check_old_integrity = 0;
    char inode_xattr_value[CHECKSUM_BUFFER_SIZE];
    char old_digest[CHECKSUM_BUFFER_SIZE];

    /* Chroot? Maybe NULL isn't right here */
    filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
	printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
	return -ENOENT;
    }
    if (!filp->f_op->read)
	return -EACCES; /* file(system) doesn't allow reads */

     strcpy(inode_xattr_value,"trusted.md5sum");
     if(flag==2)
     {
	 memset(old_digest, 0, CHECKSUM_BUFFER_SIZE);
	 check_old_integrity = get_integrity_xattr(filp,inode_xattr_value,old_digest,len);
	 if(check_old_integrity){
	    printk("Error occurred while calculating existing integrity for file in Mode2");
	    rc = check_old_integrity;
	 }
	 else{
	     	for(j=0; j <len /*mode_2_value->ilen*/; ++j) {
		 //printk("%02x", old_digest[j] & 0xFF);
		 if(old_digest[j]==0){
		     count++;
		 }
	        }
	 	if(count==len){
	     		printk("\n %s File exists with no integrity", filename);
	 	}
	 	else{
	     	   printk("\n %s File exists with old integrity", filename);
	 	}

     	 }
     }
    /* now read len bytes from offset 0 */
    filp->f_pos = 0;           
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    rc = crypt_init_desc(&desc);
    do {
	bytes = filp->f_op->read(filp, buf, len, &filp->f_pos);
	sg_init_one(sg,buf,bytes);
	rc = crypto_hash_update(&desc,sg,bytes);

    } while(bytes);

    if(!rc){
	rc = crypto_hash_final(&desc, digest);//calculate final digest and populate value in buf
    }
    crypto_free_hash(desc.tfm);
    strcpy(inode_xattr_value,"trusted.md5sum");
    if(flag==2){
	if(filp->f_mapping->host->i_op->setxattr) {
	    filp->f_mapping->host->i_op->setxattr(filp->f_dentry,inode_xattr_value, (void *)digest, CHECKSUM_BUFFER_SIZE, 0);
	} 
	else {
	    printk("\n store_hash_xattr: extended attributes not supported");
	    return -EPERM;
	}
    }

    set_fs(oldfs);

    /* close the file */
    filp_close(filp, NULL);

    return rc;
}

//Mode3

int open_file_check_integrity(void *arg, char *file_name){
    struct mode3 *argsptr=NULL;
    int ret,i,count = 0;
    int flag =3;
    int oflag =0;
    char computed_digest[CHECKSUM_BUFFER_SIZE];
    char old_digest[CHECKSUM_BUFFER_SIZE];

#if 1
    struct file *filp = NULL;
    //struct inode *node = NULL;
    char *filename = NULL;
    char *buf = NULL;
    // mm_segment_t oldfs = get_fs();
#endif

    memset(old_digest, 0, CHECKSUM_BUFFER_SIZE);
    memset(computed_digest, 0, CHECKSUM_BUFFER_SIZE);

    argsptr =(struct mode3 *)kmalloc(sizeof(struct mode3),GFP_KERNEL);
    if(argsptr==NULL){
	return -ENOMEM;
    }
    memset((void *)argsptr, 0, sizeof(struct mode3));
    ret = copy_from_user(argsptr,arg,sizeof(struct mode3));
    if(ret) {
	printk("\n Copy From User failed.");
	kfree(argsptr);
	return -EFAULT;
    }
#if 1
    oflag = argsptr->oflag;
//    printk("oflagggggggggggg %d",oflag);
    filename = getname(argsptr->filename);
    printk("\n filename :: = %s", filename);
    if(filename==NULL){
	printk("\n get_exisiting_integrity: getname failed while retrieving filename)");
	kfree(argsptr);
	return -ENOENT;
    }
    filp = filp_open(filename, oflag, 0);
    if (!filp || IS_ERR(filp)) {
	printk("\n Read File Error. No such file exists %d\n", (int) PTR_ERR(filp));
	putname(filename);
	kfree(argsptr);
	return -ENOENT;
    }
    if (!filp->f_op->read){
	printk("\n User does not have permission to read file %d\n", (int) PTR_ERR(filp));
	putname(filename);
	kfree(argsptr);
	return -EACCES; // User denied read access
    }
    if(filp) {
	if((oflag & O_TRUNC) == O_TRUNC){
	    printk("\n \n Flag value is O_TRUNC. Not calculating old checksum. Any existing checksum is set to 0");
	   }
	else if((oflag & O_CREAT)== O_CREAT)
	{
	    ret = get_integrity_xattr(filp, "trusted.md5sum", old_digest, 16);
	    for(i = 0;i<16;i++){
		if(old_digest[i]==0){
		    count++;
		}
	    }
	    if(count==16){
		printk("\n %s is a new file and its checksum is not calculated earlier. Execute mode2 to update the checksum of file", filename);
	    }
	    else{

		buf = kmalloc(FILE_CHUNK_SIZE, GFP_KERNEL);
		if(buf==NULL){
		    putname(filename);
		    kfree(argsptr);
		    return -ENOMEM;
		}

		ret = read_file_checksum(filename, buf,computed_digest, FILE_CHUNK_SIZE,flag);
		if(ret){
		    kfree(buf);
		    return ret;	
		}
		else{
		    if(strcmp(old_digest,computed_digest)){
			printk("\n Digest matches in mode3 for file: %s",filename);
			kfree(buf);
		    }
		    else{
			printk("\n digest did not match. File is corrupt");
			kfree(buf);
			return -EFAULT;
		    }
		}
	    }
	}
	else if(oflag==0 || oflag==1 || oflag==2)
	{
	    buf = kmalloc(FILE_CHUNK_SIZE, GFP_KERNEL);
	    ret = read_file_checksum(filename, buf,computed_digest, FILE_CHUNK_SIZE,flag);
	    if(ret){
		kfree(buf);
		return ret;
	    }
	    else{
		if(strcmp(old_digest,computed_digest)){
		    printk("\n Digest matches in mode3 when flag:%d",oflag);
		    kfree(buf);
		}
		else{
		    printk("\n digest did not match. File is corrupt");
		    kfree(buf);
		    return -EPERM;
		}
	    }


	}
	else{
	    printk("\n\n Invalid flag in Mode3.Not returning file Descriptor");
	    filp_close(filp,NULL);
	    putname(filename);
	    kfree(argsptr);
	    return -EFAULT;
	}
    }
    else {
	printk("\nstore_hash_xattr: file pointer is NULL. check if file is open");
	filp_close(filp,NULL);
	putname(filename);
	kfree(argsptr);
	return -ENOENT;
    }
    filp_close(filp,NULL);
    strcpy(file_name,filename);
    putname(filename);
#endif
    kfree(argsptr);
    return ret;


}

int get_fd(char *filename) {
    struct file *filp = NULL;
    int fd = 0;
    filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
	printk("Read File Error. No such file exists %d\n", (int) PTR_ERR(filp));
	return -ENOENT;
    } 
    fd = get_unused_fd();
    fd_install(fd, filp);
    printk("\n calculated fdddddd--> %d",fd);
    filp_close(filp, NULL);
    return fd;
}

int crypt_init_desc(struct hash_desc *desc)
{
    char algotype[] = "md5";
    int rc;
    desc->tfm = crypto_alloc_hash(algotype, 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(desc->tfm)) {
	pr_info("failed to load %s transform: %ld\n", algotype, PTR_ERR(desc->tfm));
	rc = PTR_ERR(desc->tfm);
	return rc;
    }
    desc->flags = 0;
    rc = crypto_hash_init(desc);
    if (rc)
	crypto_free_hash(desc->tfm);
    return rc;
}

//Function to get existing integrity of file.
int get_integrity_xattr(struct file * filp, char * xattribute, char * digest, int digestlen)
{
    struct inode * finode = NULL;
    if(filp) {
	finode = filp->f_mapping->host;
	if(finode->i_op->getxattr) {
	    finode->i_op->getxattr(filp->f_dentry, xattribute, (void *)digest, digestlen);
	} else {
	    printk("\nstore_hash_xattr: extended attributes not supported");
	    return -EPERM;
	}
    } else {
	printk("\nstore_hash_xattr: file pointer is NULL. check if file is open");
	return -ENOENT;
    }
#if 0
    for(j=0; j < 16 /*mode_2_value->ilen*/; ++j) {
	printk("%02x", digest[j] & 0xFF);
	if(digest[j]==0){
	    count++;
	}
    }
    if(count==16){
	printk("\n 1111  File exists with no integrity");
    }
    else{
	printk("\n 222 File exists with old integrity");
    }
#endif
    return 0;
}
int validate_password(char *credbuf,int length)
{
    int match=0;
    int pwd_check_result =0;
    if(credbuf!=NULL || length== (unsigned int)strlen((char*)credentials)){
	match = strcmp(credbuf,credentials);
	if(match==0){
	    pwd_check_result =1;
	}
    }
    return pwd_check_result;
}

static int __init init_sys_xintegrity(void)
{
    printk("installed new sys_xintegrity module\n");
    if (sysptr == NULL)
	sysptr = xintegrity;
    return 0;
}
static void  __exit exit_sys_xintegrity(void)
{
    if (sysptr != NULL)
	sysptr = NULL;
    printk("removed sys_xintegrity module\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");
