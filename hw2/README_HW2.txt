
********************************************************************************************
README.HW2
********************************************************************************************
Using the wrapfs stackable filesystems, the project adds integrity checking feature to the regular 
files and directories in the underlying ext3 filesystem.
The description is as follows.

Files modified: fs/wrapfs/wrapfs.h
				fs/wrapfs/inode.c
				fs/wrapfs/file.c
				fs/wrapfs/Makefile
				hw2-anaagarwal/user.config

Files added:  fs/wrapfs/xattr.c
			  fs/wrapfs/computeChecksum.c
			  hw2-anaagarwal/install_module.sh
			  hw2-anaagarwal/README_HW2.txt
			  fs/wrapfs/xattr.h
			  
			  
Usage of installation script file
Mount ext3 filesystem with extended attributes enabled.
command: #mount -t ext3 /dev/sdb1 /n/scratch -o user_xattr
(If lower file system is not mounted with this attribute enabled which means it does not support EA, 
wrapfs implementation throws error "operation not supported".

umount the already existing filesystem on  /tmp (if any)
The script runs in the following order:
   #umount /tmp/

   removes the wrapfs module (if one exists).
   #rmmod fs/wrapfs/wrapfs
   
   
   #make
   #make modules
   #make modules_install install

   #insmod fs/wrapfs/wrapfs.ko

   mounts the /tmp on top of /n/scratch where ext3 is already mounted.
   #mount -t /n/scratch /tmp -o user_xattr

Namespace used throughout is : "user" namespace	
fs/wrapfs/xattr.c :

		The 4 extended attributes functions as wrapfs level are implemented in this file.
		The methods are implemented in stackable file system and acts as if a call is coming from vfs to ext3 and vice versa.
		
		This files has 4 functions namely 
		
		wrapfs_setxattr(): set EA for files/directories. Condtions checked:
		1) Sets the other attributes as EA apart from integrity_val and has_integrity.
		2) Does not allow any user/root user to set the value of integrity_val from command line.
		3) if has_integrity=0, function does not set integrity_val
		4) if has_integrity = 1, function called computeChecksum is called and checksum is by default calculated for MD5 algorithm.
		5) if user changes has_integrity from 1 to 0, integrity_val is removed as an EA.
		6) has_integrity is set only for directories and regular files.
		7) Only root user is allowed to set has_integrity attribute.
		
		wrapfs_getxattr():  get EA for files/directories. Condtions checked:
		1) Any user is allowed to view the extended attributes.
		2) If EA is not set , function throws an error.
					
		wrapfs_removexattr():  removes EA for files/directories. Condtions checked:
		1)User is not allowed to delete integrity_val from command line.
		2) If user removes has_integrity then integrity_val is also removed.
	
		
		wrapfs_listxattr(): lists all the attributes of the file.
		No condition checks, as it internally calls getxattr.
		
fs/wrapfs/inode.c

		wrapfs_create():
		1) Added new functionality of setting has_integrity and integrity_val if parent directory has it set.
		2) Saved 1 computation of checksum by saving the default value of checksum in a constant variable. Its a default MD5 checksum.
		 
		wrapfs_mkdir(): 
		1) Whenever a new directory is created , if parent directory contains has_integrity, the sub directory also inherits it.
		2) If for the parent directory "has_integrity" is changed for 0-1 or removed, existing files/directories are not affected.
     	   However, new files/directories inherit the changed property.
	
	
fs/wrapfs/file.c

		wrapfs_write(): 
		This function is called when process writes into the file. The flag dirty_flag is set, if process writes into the file.

		wrapfs_open():
		1) If a file is regular file and have EA "has_integrity" =1, then checksum is computed and is compared with the stored checksum.
		2) If checksum matches the files open.
		3) There is a possibility that 2 processes are working on same file. In this case after comparing the checksums, if they mismatch, and if dirty flag = true,
		then checksum is updated and file is opened without any error,otherwise, permission denied message is shown to the user and file is not opened.
		(Tested using echo command)
		4)This function takes care of various flags set for the file. Opening the file with truncate,create,append and read mode are taken care in this function.
	
		wrapfs_release():
		This function is called, when the process closes the file. In this function, we check to see if "has_integrity" is 1. If so, we check to see
		if dirty_flag is set. If it is set, checksum for the file is recalulated and updated in the extended attribute. Once the checksum is updated,
		dirty_flag is set back to 0.
		
fs/wrapfs/computeChecksum.c	

    	wrapfs_compute_checksum():
		This function is used to calcualte the checksum of the file. 
	
		str_to_hex(): is the function used to convert the calculated checksum to ascii value.
	
fs/wrapfs/wrapfs.h
		Has all the declarations. Dirty flag is added to wrapfs_inode_info structure as d_flag. 
		Constant value for default MD5 checksum and digest length is added.
		
fs/wrapfs/xattr.h
Includes constants for xattr.c
	
References:

1) http://www.linuxquestions.org/questions/programming-9/hex-to-ascii-and-ascii-to-hex-580756/
2) Unionfs code for EA
3) Understanding the Linux kernel.
4) Wrapfs code- author: Erez Zadok.
	
							  