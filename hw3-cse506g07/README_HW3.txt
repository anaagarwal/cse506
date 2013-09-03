/* 					README
 * CSE-506 Operating System (Spring 2013) Homework Assignment #3
 * ADDRESS SPACE OPERATIONS AND ENCRYPTION/DECRYPTION FILE IN WRAPFS
*/

We have succesfully supported implementation of VM_OP and Address space operation and encryption and decryption
of file data/pages in wrapfs. We have also implemented Extra credits for Debug operations 
and filename encryption.Decryption works fine with the function but we were not able to 
integrate with the function of wrapfs due to lack of time and resource, but it does encrypt
and decrypt filename.Encryption of filename is done for lookup and symlink functions.


**************************************************************************************************************************************
NEW FILES added in the system.
**************************************************************************************************************************************


1) fs/wrapfs/computeKey.c : The file is used to generate 32 bytes key from a string send through wrapfs_unlocked_ioctl method. The key is used for file/filenames encryption/decryption.
				  
2) /usr/src/hw3-cse506g07/user_ioctl_test.c : The file uses a method to call ioctl. The ioctl in turns calls wrapfs_unlocked_ioctl and code to generate key is defined in #ifdef. It will generate key only if WRAPFS_CRYPTO is enabled. Here we are considering a constant length input string to the ioctl.

3) /usr/src/hw3-cse506g07/user_lseek_test.c : This is a user program for testing the lseek operation on writing and reading data from the
pages of the file. we have used this program to fill in the zeros while encrypting the pages.

4) fs/wrapfs/filename_encrypt.c : This file contains the function used for filename encryption and decryption.wrapfs_encode_filename and wrapfs_decode_filename encodes and decodes the filenames respectively. They make use of fucntions which are defined in 
file or the header file wrapfs.h like BF_cfb64_encrypt function which is in this file. It is the EXTRA_CREDIT_2.

5) /usr/src/hw3-cse506g07/install_module.sh

To increase efficiency,we decided to make a script file which is as follows.

umount /mnt
cd /
rmmod wrapfs
cd /usr/src/hw3-cse506g07
make
make modules
make modules_install install
mount -t wrapfs /n/scratch/ /mnt -o mmap

To mount with debug option enabled we just need to change 

mount -t wrapfs /n/scratch/ /tmp -o mmap,debug=X , where X is the number for which we need to enable the debug option as stated in HW3 writeup.

**************************************************************************************************************************************
COMPILATION:
**************************************************************************************************************************************

1. kernel.config should be used for added compiled options.
2. fs/wrapfs/Makefile contains executable(user_ioctl_test) for user_ioctl_test.c . This will generate key. To revoke key pass value as "000000" in makefile
3. WRAPFS_CRYPTO and EXTRA_CREDIT_1:debug EXTRA_CREDIT_1:filename encryption/decryption can be enabled and disabled in wrapfs.h.
4. User programs have to be executed to set key. To set key: gcc -o a.out user_ioctl_test.c 'some string of length less than 10'.
   to revoke key: gcc -o a.out user_ioctl_test.c '00000'.
5. We have provided user program to test for sleek functionality. user_lseek_test.c.
6. user_lseek_test.c can be tested for O_TRUNC, O_RDWR flags also. 


**************************************************************************************************************************************
FILES MODIFIED :-
**************************************************************************************************************************************

 fs/wrapfs/wrapfs.h
 fs/wrapfs/main.c
 fs/wrapfs/mmap.c
 fs/wrapfs/dentry.c
 fs/wrapfs/file.c
 fs/wrapfs/inode.c
 fs/wrapfs/lookup.c
 fs/wrapfs/super.c
 kernel.config file used same as of HW2: just included support for AES encryption and CTR mode support.
 j-ltp.sh(added option for mmap while mounting wraps with mmap)
 fs/wrapfs/Makefile
**************************************************************************************************************************************
IMPLEMENTATION :---
**************************************************************************************************************************************

TASK1:-
==================================
mknod issues that popped up in assignment2 while running LTP were fixed in wrapfs_create method. Added a check for namespacedata is not null which fixed the issue. Also, address space operations without encryption are working fine except syscall - splice02. LTP for address space operations can be tested after commenting splice02. Have not tested for encryption

TASK2:- ADDRESS SPACE OPERATIONS
==================================

The wraps code currently only implement vm_ops. We have tried to implement address space operations(aops). If wraps is mounted with mmap option, then the support for address space operations is enabled. If WRAPFS_CRYPTO is enabled then address space operations supports encryption/decryption of file.

use: mount -t wrapfs /n/scratch/ /tmp -o mmap

To enable and disable we are making use of int variable mmap_option_set. This flag variable is declared in the superblock structure in wrapfs.h
and used in main.c to enable and disable the mmap option. Also we have included a char* variable for key in superblock structure.
wrapfs_parse_options function is created in main.c which parses the options we recieve in runtime. So, when we recieve mmap, it enables the flag and set it to 1, otherwise it is set to 0 and normal operations are executed.

When mmap_option_set is set to 1 , then we check in lookup.c struct inode *wrapfs_iget function to enable the mmap functions.Otherwise, normal fops are run.

in mmap.c a structure is created to register mmap operations

const struct address_space_operations wrapfs_mmap_aops = {
    .writepage      = wrapfs_writepage,
    .write_end		= wrapfs_write_end,
    .write_begin	= wrapfs_write_begin,
    .readpage		= wrapfs_readpage,
	.bmap			= wrapfs_bmap,	
};

also, in file.c we have created another structure to support mmap operations.

const struct file_operations wrapfs_main_mmap_fops = { 
    .llseek         = generic_file_llseek,
    .read           = do_sync_read,
    .write          = do_sync_write,
    .aio_read  		= generic_file_aio_read,
    .aio_write 		= generic_file_aio_write,
    .unlocked_ioctl = wrapfs_unlocked_ioctl,
	.mmap			= generic_file_mmap,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = wrapfs_compat_ioctl,
#endif
    .open           = wrapfs_open,
    .flush          = wrapfs_flush,
    .release        = wrapfs_file_release,
    .fsync          = wrapfs_fsync,
    .fasync         = wrapfs_fasync,
};

Now, once they are enabled, it runs the function defined in mmap.c

wrapfs_read and wrapfs_write handle read/write differently based on mmap_option_set.
If mmap option is set, do_sync_read/do_sync_read is called on wrapfs file which inturn invoke wrapfs_readpage/wrapfs_writepage. 
When it is 0, a plain vfs_read/vfs_write on lower_file is called.


These are the functions implemented and referenced from ecryptfs. this function contains code for encrypting and decrypting file pages. It is explained in next section.

**************************************************************************************************************************************
TASK 3: DATA PAGE ENCRYPTION
**************************************************************************************************************************************

To encrypt and decrypt we have made use of the function wrapfs_encrypt and wrapfs_decrypt in the mmap.c. To make this working we had to enable the AES and CTR cipher for encryption in the kernel config.
We have created a user ioctl program that generates the key for encrypting and decrypting data pages,
Key is being stored in the structure of superblock wrapfs_struct_info and used with the superblock object wherever required. Before revoking/resetting/updating the key dentry cache is cleaned up. Also, user is warned before any of the actions take place.

1) wrapfs_writepage - The code for writepage is taken from ecryptfs and implemented for part 1 of address space
operations. significant changes are done for part 2 of data encryption and ecryption.

2)wrapfs_readpage - The code for writepage is taken from ecryptfs and implemented for part 1 of address space
operations. significant changes are done for part 2 of data encryption and ecryption.

3)wrapfs_write_begin: we have referenced the function from ecryptfs. write_begin sets up the page for writing. If page is not updated we are reading it from lower file system. Also if encryption is enabled we read from lower file system and decrypt the data first.

 --If WRAPFS_CRYPTO is disabled, then just grab the page and set it up for write_begin. It is almost similar to ecryptfs. lseek/fseek is handled accordingly.      
   When we seek to a position after EOF and skip pages in between, the page to be written in filled with zeroes if the offset from where we have to write              is not 0. The zeroes are filled till offset and then the text is written. The remaining pages are not truncated as done by Ecryptfs, rather we have left them to be taken care by ext3 itself.
 --When WRAPFS_CRYPTO is enabled, we have handled 3 possible cases as mentioned below:
		1. The page to write is same as last page in original file. We need to fill zeroes
		   upto the positon where write begins. 
		2. The page to write is an intermediate file page. We don't need to do anything here.
		3. If we skip to a page more than the last page in file, then we need to fill 
		   holes between current last page and the index of page to be written. All these pages
		   are marked as dirty.
Also, we are not reading from the lower filesystem if index from where we have to write > existing in ode index as we don't require older pages for encryption chaining. Thus saving unnecessary reads.

4)wrapfs_write_end: If WRAPFS_CRYPTO is enabled, page is encrypted before writing to lower filesystem else normal write to lower file system takes place.

5)wrapfs_bmap: This function is directly taken from ecryptfs. No changes are made to this.


**************************************************************************************************************************************
EXTRA CREDITS:-
**************************************************************************************************************************************

1)Debugging/tracing support

We have implemneted the debugging support for the different blocks as mentioned in the writeup. To enable this debug extra credit,Enable the #define EXTRA_CREDIT_1 in the wrapfs.h .

For this, we have mnade changes in main.c .firstly, flags for all six debug operations are defined in the super block struct info in wrapfs.h and also in the main .c locally.

#ifdef EXTRA_CREDIT_1
	int debug_super_block_ops;
	int debug_inode_ops;
	int debug_dentry_ops;
	int debug_file_ops;
	int debug_address_space_ops;
	int debug_all_other_ops;
#endif

set_enable_debug function is made in main.c which enables the debug for the respective blocks. The macro is enabled as per the given options below.	

0x01: enable debugging for superblock ops
0x02: enable debugging for inode ops
0x04: enable debugging for dentry ops
0x10: enable debugging for file ops
0x20: enable debugging for address_space ops
0x40: enable debugging for all other ops

for eg: mount -t wrapfs \n\scratch \tmp -0 mmap,debug=32

it enables debug for address space operations as 32 in decimal is 20 in hex decimal.So, it enables debug suppport for address space.

	mount -t wrapfs \n\scratch \tmp -0 mmap,debug=3
so this'll enable debugging for superblock and inode ops

Also,
	mount -t wrapfs \n\scratch \tmp -0 mmap,debug=0
if we mount it with debug=0 , then the debug is disbaled and we do not get any printks.

As far as remount condition goes, it does remount with the option 0, but debug options are not disbaled in that case, we havmnt taken care of that.

Our debug operation works for the specific values and the combination of that as mentioned in the writeup, but no check is made for arbitary values. So, it only runs valid in the case of mentioning right values in it.Passing arbitary values may enable other debug operations which we havent handle. But normal debug works.

We have looked into ecryptfs custom printk statement making use of UDBG printk to define our own as stated in writeup for assignment.

eg: #define debug_super_block_ops(flag, fmt, arg...) \ 
	flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;
		
if the value for this flag is 1, then it is enable and printk are printed. if it is 0, then it does not.

There are two printk statements enabled in each function. One at the start of it displaying the function name it is in, and one at the end of it displaying the err number returned by the function.

Necessary printk are then added in the files for specific type like inode.c for inode operations,file.c for file  operations and similarly for  dentry.c, super.c, mmap.c for address space operation and for all other operations
the printks are define in wrapfs_fault function in mmap.c

It is also implemented in lookup.c depending upon the operations defined inside the functions. so, we make use of inode operation, dentry operation as specified there.


**************************************************************************************************************************************
2) FILENAME ENCRYPTION AND DECRYPTION
**************************************************************************************************************************************

-- To enable this extra credit , we need to enable #define EXTRA_CREDIT_2 in the wrapfs.h.Also, we have to enable WRAPFS_CRYPTO to generate key.
-- Encryption/Decryption uses Blowfish as used in fistegen. The code is in file wrapfs/filename_encrypt.c.
-- Key used is similar to one we are using for file data encryption/decryption and has to be generated via ioctl.
-- The functionality is partially implemented. Encryption for filenames has been implemented for functions in lookup.c and for symlink function.
-- Normal decryption function is working but is not implemented for functions READDIR(), FILLDIR(). 
-- As a result our functionality can encrypt filenames and encrypted names are visible but due to lack of time were not able to implement decryption.
-- #ifdef EXTRA_CREDIT_2 #endif contains only encryption functionality. Decryption method is present there and printk's are commented. To test the   decrypt method only they can be uncommented and filenames can be explicitly passed to check the working function.


*****************************************************************************************************************************************
EXTRA IMPLEMENTATIONS:-
*****************************************************************************************************************************************

1) We choose to shrink wrapfs's dcache whenever the key was set, revoked, or reset using method: shrink_dcache_sb().
This design decision was made as the pages that were just read with a previous key were still in the cache and readpage was not called when we try to read the file with a new key and old contents were displayed.

2) Key generation takes place using MD5 algorithm. The function is defined in computeKey.c. A 32-byte key is generated from string passed through

3) Both the extra credits are implemented. one is done partially as mentioned above. 

*****************************************************************************************************************************************
TESTING
*****************************************************************************************************************************************

1) Run LTP to support address space operations. Generate key, enable necessary flags in wrapfs.h and then run ltp for address space. 
Need to comment splice02 in sys calls file. It failed.
2) Lseek seems to work fine most of the times. Although we have noticed some strange behavior after we test it for multiple times some garbage is visible 
at the end of 1 other page that too in a small segment. Data is encrypted and decrypted fine.
3) Did not run LTP for encryption in address space operations.
4) To test for debugging enable it in wraps.h and mount wrapfs with suitable option. 
5) To test file encryption enable extracredit2 in wrapfs.h. Decryption of files is not handled but a running method is there which works perfectly fine.


*****************************************************************************************************************************************
RESOURCES and CITATIONS:
*****************************************************************************************************************************************

1) ECRYPTFS CODE and UNIONFS Code
2) FISTGEN Encrypting and decrypting filenames
3) http://www.makelinux.net/ldd3/chp-4-sect-2 for referencing custom printk statements
4) http://lxr.linux.no/linux+v3.2/fs/ecryptfs/ecryptfs_kernel.h#L515 for referencing curom printk in ecryptfs
5) Linux LXR for code and understanding some syntax.
			  