
/* This file is a user program defined for ioctl operation
 * It is used for transferring a string to wrapfs_unlocked_ioctl
 * and and then computing the key. 
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
  char *val = NULL;
  char *filename = argv[1];
  if (argc != 3)
    {
      printf("ERROR in passing arguments\n");
      return -1;
    }
  val = argv[2];
  /*length of the string must be 10*/
  if ((val == NULL) || (strlen(val) > 10)) {
    printf("Key is Invalid\n");
  }
  fd = open(argv[1], O_CREAT | O_RDONLY);
  ret = ioctl(fd,WRAPFS_IOCSETD,val);
  printf("return value from ioctl-- > %d \n",ret);
  if(ret == -1) 
    err(1,"CRYPTFILE! \n");
  close(fd);
  return 0;
}

