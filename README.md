cse506
======

Implementation of system call to enable integrity check on files (Linux 2.6)
February 2013
Implemented a system call to set and check the integrity of files in file system. Once the feature is turned on by the system call, for every new file that is created, MD5 checkum is calculated and saved as metadata of file. When the user tries to open the file again, integrity is checked to verify if any illegitimate changes have occurred to file. Only after integrity matches, file is opened.

Implementing Filesystem level Encryption using Stackable Filesystem model
April 2013
Added features like Address spce operations, Extended attrivbute support, integrity check methods to a null-layer stackable Filesystem called Wrapfs, to place it over EXT4. On creating any file to be saved in EXT4, data encryption is first done in Wrapfs layer and the encrypted data gets saved in EXT4. Hence making it difficult for illegitimate user to retrieve data from Filesystem
