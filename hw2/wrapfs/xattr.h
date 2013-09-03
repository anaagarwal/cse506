#define _XATTR_H_


enum checksum_type{
    md5,
    SHA1
};

char * integrity_val_EA= "user.integrity_val";
char * has_integrity_EA= "user.has_integrity";
char * checksum_algorithm = "md5"; 
int MD5_CHECKSUM_VAL = 33;
int MD5_CHECKSUM_BUF = 17;
