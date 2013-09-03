#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "syscall_xintegrity.h"
#include <fcntl.h>
#define __NR_xintegrity	349	/* our private syscall number */

int main(int argc, char *argv[])
{    
    int rc,i,count=0;
    unsigned char checksum_buf[CHECKSUM_BUFFER_SIZE];
    char flag;
    char *filename = NULL;
    unsigned char *password = NULL;
    struct mode1 * mode_1 = NULL;
    struct mode2 * mode_2 = NULL;
    struct mode3 * mode_3 = NULL;
    void * syscall_mode = NULL;
   // int fd =0;
    flag = argv[1][0];
    filename = argv[2];

    switch(flag) {
	case '1':
	    if(argc<3){
		printf("Invalid number of arguments");
	    	return EXIT_FAILURE;
	    }
	    else{
	    mode_1 = (struct mode1 *)malloc(sizeof(struct mode1));
	    }
	    if(!mode_1) {
		return EXIT_FAILURE;
	    }
	    memset((void *)mode_1, 0, sizeof(struct mode1));

	    mode_1->flag     = (char)flag;
	    mode_1->filename = filename;
	    mode_1->ibuf     = checksum_buf;
	    mode_1->ilen     = 0;
	    syscall_mode =(void*)(mode_1);
	    break;
	case '2':
	    if(argc<4){
		 printf("Invalid number of arguments");
		return EXIT_FAILURE;
	    }
	    else{
		mode_2 = (struct mode2 *)malloc(sizeof(struct mode2));
		}
	    if(!mode_2) {
		return EXIT_FAILURE;
	    }
	    memset((void *)mode_2, 0, sizeof(struct mode2));
	    password = (unsigned char *)argv[3];
	    mode_2->flag     = (char)flag;
	    mode_2->filename = filename;
	    mode_2->ibuf = checksum_buf;
	    mode_2->ilen = 0;
	    mode_2->credbuf = password;
	    mode_2->clen = (unsigned int)strlen((char *)password);
	    syscall_mode =(void*)mode_2;
	    break;
	case '3':
	    if(argc<3){
		printf("\n Invalid number of arguments");
		return EXIT_FAILURE;
	    }
	    else{
	    mode_3 = (struct mode3 *)malloc(sizeof(struct mode3));
	    }
	    if(!mode_3) {
		return EXIT_FAILURE;
	    }
	    memset((void *)mode_3, 0, sizeof(struct mode3));

	    mode_3->flag = (char)flag;
	    mode_3->filename = filename;
	    mode_3->oflag = atoi(argv[3]);
	    printf("oflagggg-->%d", atoi(argv[3]));
	    mode_3->mode = 0;
	    syscall_mode =(void*)(mode_3);
	    break;
	default:
	    printf("\n%s: Invalid flag %d", argv[0], flag);
    }

    rc = syscall(__NR_xintegrity,syscall_mode);
#if 0
    for(i=0;i<16;i++){
	printf("%02x",args.ibuf[i]);
    }
# endif
    switch(flag) {
	case '1':
	   // printf("\nFilename: %s, HashLength(%d)\n: ", mode_1->filename, mode_1->ilen);
	    for(i = 0; i < 16 /*mode_2_value->ilen*/; ++i) {
		if( mode_1->ibuf[i]==0){
		    count++;
		}
	    }
	    if(count==16){
		printf("File Integrity is not set for file %s", mode_1->filename);
	    }
	    else if(errno==1){
		printf("Extended attributes are not set up to read integrity of file- %s",mode_1->filename);
	    }
	    
	    else if(errno ==2){
	    	printf("%s -File does not exists",mode_1->filename);
	    }
	    else if(errno==13){
	      printf("User does not have read permissions on file- %s",mode_1->filename);
	    }
	    else if(errno==0){
		printf("File Integrity exists for file %s", mode_1->filename );
		printf("\n HashLength(%d) : ", mode_1->ilen);
		printf("\n HashValue :");
		for(i = 0; i < 16 /*mode_2_value->ilen*/; ++i) {
		    printf("%02x", mode_1->ibuf[i] & 0xFF);
		}
	    }
	    else{
	    	printf("Unknown error occurred, errno= %d",errno);
	    }

//	    for(i = 0; i < 16 /*mode_1_value->ilen*/; ++i) {
//		printf("%02x", mode_1->ibuf[i] & 0xFF);
//	    }

	    free(mode_1);
	    break;

	case '2':
	    
	    for(i = 0; i < 16 /*mode_2_value->ilen*/; ++i) {
		if( mode_2->ibuf[i]==0){
		    count++;
		}
	    }
	    if(count==16){
		printf("\n File Integrity is not set for file %s", mode_2->filename);
	    }
	    else if(errno==1){
		printf("\n Extended attributes are not set up to read integrity of file- %s",mode_2->filename);
	    }

	    else if(errno ==2){
		printf("%s -File does not exists",mode_2->filename);
	    }
	    else if(errno ==12){
		printf("Buffer cannot be allocated. Out of memory");
	    }
	    else if(errno==13){
		printf("\n Permission denied:Invalid/wrong password OR User does not have read/write permission");
	    }
	    else if(errno==0){
		printf("\n File Integrity exists for file %s", mode_2->filename );
		printf("\n HashLength(%d) : ", mode_2->ilen);
		printf("\n HashValue :");
		for(i = 0; i < 16 /*mode_2_value->ilen*/; ++i) {
		    printf("%02x", mode_2->ibuf[i] & 0xFF);
		}
	    }
	    else{
		printf("\n\n Unknown error occurred, errno= %d",errno);
	    }

	   free(mode_2);
	    break;
	case '3':
	    if(rc < 0) {
		printf("\nFilename: %s, File Descriptor could not be opened\n", mode_3->filename);
		//exit(rc);
	    }
	    else if(errno==1){
		printf("\n Extended attributes are not set up to read integrity of file- %s",mode_3->filename);
	    }

	    else if(errno ==2){
		printf("%s -File does not exists",mode_3->filename);
	    }
	    else if(errno ==12){
		printf("Buffer cannot be allocated. Out of memory");
	    }
	    else if(errno==13){
		printf("\n Permission denied:User does not have read/write permission");
	    }
	    else if(errno==0){
		 printf("\nFilename: %s opened. fd = %d ", mode_3->filename,rc);
	    }
	    else{
		printf("\n\n Unknown error occurred, errno= %d",errno);
	    }


//	    printf("\nFilename: %s opened. fd = %d ", mode_3->filename,rc);
	    free(mode_3);
	    break;

	default:
	    printf("\n%s: Invalid flag %c", argv[0], flag);
	    //free(syscall_mode);
	 //   return EXIT_FAILURE;

      }
    
    if (rc == 0)
	printf("\n syscall returned %d\n", rc);
    else if (flag==1 || flag==2){
	printf("\n syscall returned %d (errno=%d)\n", rc, errno);
    }

    exit(rc);

}
