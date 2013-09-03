# include "wrapfs.h"

int str_to_hex_str(char * str, char * hex, int hex_len, int str_len);
void hexify_ascii(char c, char * buf);

int crypt_init_desc(struct hash_desc *desc,char *checksum_algorithm);

int wrapfs_compute_checksum(struct file* filp, char* buffer, char *checksum_algorithm) {
    struct scatterlist sg[1];
    struct hash_desc desc;
    mm_segment_t oldfs;
    int bytes, rc =0;
    // int diglength = 16;
    int length = PAGE_SIZE;
    unsigned char buf[DIGESTLEN+1];
    char *read_in_buffer = NULL;
    memset(buf,0,DIGESTLEN+1);  
    read_in_buffer = kmalloc(length, GFP_KERNEL);
    if(read_in_buffer == NULL) {
	kfree(read_in_buffer);
	printk("Error in allocating memonry in checksum block.\n");
	return -ENOMEM;
    }

    filp->f_pos = 0;           
    oldfs = get_fs();
    set_fs(KERNEL_DS);

    rc = crypt_init_desc(&desc,checksum_algorithm);
    do {

	bytes = filp->f_op->read(filp, read_in_buffer, length, &filp->f_pos);
	sg_init_one(sg,read_in_buffer,bytes);
	rc = crypto_hash_update(&desc,sg,bytes);

    } while(bytes);

    if(!rc) {
	rc = crypto_hash_final(&desc, buf);//calculate final digest and populate value in buf
#if 0	
	printk("\n printing checksum in compute checksum \n");
	for(i =0;i<16;i++){
	    printk("%02x",buf[i]& 0XFF);
	    //	    buffer[i] = buf[i];
	}
#endif
    }

    rc =  str_to_hex_str(buf, buffer, DIGESTLEN*2 +1, DIGESTLEN);
    crypto_free_hash(desc.tfm);

    set_fs(oldfs);
    kfree(read_in_buffer);
    return rc;
}

int crypt_init_desc(struct hash_desc *desc, char *checksum_algorithm) {
    int rc;
    desc->tfm = crypto_alloc_hash(checksum_algorithm, 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(desc->tfm)) {
	pr_info("failed to load %s transform: %ld\n", checksum_algorithm, PTR_ERR(desc->tfm));
	rc = PTR_ERR(desc->tfm);
	return rc;
    }
    desc->flags = 0;
    rc = crypto_hash_init(desc);
    if (rc)
	crypto_free_hash(desc->tfm);
    return rc;
}

void hexify_ascii(char c, char * buf) {
    int high = (c >> 4) & 0xF;
    int low = c & 0xF;
    *buf       = (high < 0xA) ? high + 48 : high + 87;
    *(buf + 1) = (low < 0xA) ? low + 48 : low + 87;
    // printk("\n sup: c = %x, high = %x, low = %x", c, high, low);
}

int str_to_hex_str(char * str, char * hex, int hex_len, int str_len) {
    int i,ret=0;
    char * ptr = hex;
    // printk("\n strlen--> %d",str_len);

    if (str_len * 2 > hex_len) {
	return -1;              /* str won't fit in hex */
    }
    for (i = 0; i < str_len; i++) {
	hexify_ascii(str[i], ptr);
	ptr += 2;
    }

    *ptr = '\0';

    return ret;
}

