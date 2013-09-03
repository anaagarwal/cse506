
/* This file is a user program defined for lseek operation
 * It is used for transferring sursor of the file to any 
 * position desired. it is used in file reading and writing data
 * from the specified posoition in the lseek command. in our
 * program it is also used for checking and filling of zeros in 
 * encrypted and decrypted data. 
 */
 
#include <err.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define WRAPFS_MAGIC 's'
#define WRAPFS_IOCSETD  _IOW(WRAPFS_MAGIC, 2 , char *)

int main(int argc, char*argv[])
{
  int fd,i,rc; 
  int ret = 0,len;
  char *val;
  val = "rohanmanishanchal";
  char *filename = argv[1];
  fd = open(argv[1], 'r');
  printf("in user, file descriptor is %d \n", fd);
  ret = lseek(fd,20000,SEEK_END);
  write(fd,val,strlen(val));   
  printf("return value from lseek-- > %d \n",ret);
  if(ret == -1) 
    err(1,"CRYPTFILE! \n");
  close(fd);
  return 0;
}
