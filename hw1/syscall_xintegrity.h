

struct mode2 {
	unsigned char flag;
	const char *filename;
	unsigned char *ibuf;
	unsigned int ilen;
	unsigned char *credbuf;
	unsigned int clen;

};

struct mode3{
	unsigned char flag;
	const char *filename;
	int oflag;
	int mode;
};

struct mode1{
	 unsigned char flag;
        const char *filename;
        unsigned char *ibuf;
        unsigned int ilen;
};

int read_file_checksum(const char *filename, char *buf, char *digest, int len, int flag);
int validate_password(char *credbuf,int length);
const char credentials[] = "AncMode@";
const  char inode_xattr_value[] = "trusted.md5sum";
int compute_updated_integrity(void *arg);
int get_existing_integrity(void *arg);
int open_file_check_integrity(void *arg, char *filename);
int get_fd(char * filename);

#define CHECKSUM_BUFFER_SIZE (16)
#define FILE_CHUNK_SIZE (PAGE_SIZE)
#define FILE_NAME_SIZE (1024)
