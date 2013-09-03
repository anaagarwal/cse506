
/* 							EXTRA_CREDIT_2
 * This file contains the function used for filename encryption and decryption.
 * These function are implemented and taken from Fistgen source code available
 * to us.wrapfs_encode_filename and wrapfs_decode_filename encodes and decodes 
 * the filenames respectively. They make use of fucntions which are defined in 
 * file or the header file wrapfs.h like BF_cfb64_encrypt function which is 
 * in this file. 
 */

#include "wrapfs.h"

#ifdef EXTRA_CREDIT_2
		
extern unsigned char global_iv[8];

unsigned char global_iv[8] = {
  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

#define MAXPATHLEN PATH_MAX

int wrapfs_encode_filename(const char *name, int length,char *key,char *encoded_buf)
{
  char *crypted_name = NULL, *encoded_name = NULL;
  const char *ptr;
  int rounded_length = 0, encoded_length, n, i, j,enc_len=0;
  unsigned char iv[8];
  short csum;
	
  encoded_length = length + 1;
    
  for (csum = 0, i = 0, ptr = name; i < length; ptr++, i++)
    csum += *ptr;
  /*
   * rounded_length is an multiple of 3 rounded-up length
   * the encode algorithm processes 3 source bytes at a time
   * so we have to make sure we don't read past the memory
   * we have allocated
   *
   * it uses length + 3 to provide 2 bytes for the checksum
   * and one byte for the length
   */
  rounded_length = (((length + 3) + 2) / 3) * 3;
  if (rounded_length > MAXPATHLEN) 
    { /* check for corruption */
      encoded_length = -ENAMETOOLONG;
      goto out;
    }
  crypted_name = kmalloc(rounded_length,GFP_KERNEL);
  if (!crypted_name) 
    {
      encoded_length = -ENOMEM;
      goto out;
    }
 
  memcpy(iv, global_iv, 8);
  n = 0;
  *(short *) crypted_name = csum;
  crypted_name[2] = length;
  BF_cfb64_encrypt((char *) name, crypted_name + 3,
		   length, (BF_KEY *) key, iv, &n,
		   BF_ENCRYPT);
  /*
   * clear the last few unused bytes
   * so that we get consistent results from encode
   */

  for (i = length + 3; i < rounded_length; i++)
    crypted_name[i] = 0;
 
  encoded_length = (((length + 3) + 2) / 3) * 4 + 1;

  if (encoded_length > MAXPATHLEN) 
    { /* check for corruption */
      encoded_length = -ENAMETOOLONG;
      goto out;
    }

  encoded_name = kmalloc(encoded_length,GFP_KERNEL);

  if (encoded_name == NULL) 
    {
      encoded_length = -ENOMEM;
      goto out;
    }

  for (i = 0, j = 0; i < rounded_length; i += 3, j += 4) 
    {
      (encoded_name)[j] = 48 + ((crypted_name[i] >> 2) & 63);
      (encoded_name)[j + 1] = 48 + (((crypted_name[i] << 4) & 48) | ((crypted_name[i + 1] >> 4) & 15));
      (encoded_name)[j + 2] = 48 + (((crypted_name[i + 1] << 2) & 60) | ((crypted_name[i + 2] >> 6) & 3));
      (encoded_name)[j + 3] = 48 + (crypted_name[i + 2] & 63);
    }
  (encoded_name)[j] = '\0';
	
  /* Memcopying the encoded_name into buf to pass */	
  memcpy(encoded_buf,encoded_name,encoded_length);
  enc_len=strlen(encoded_name);
	
  /* Enable this function and printk to see decrypted name as we didn't implemented 
   * in the wrapfs functions. also, inside wrapfs_decode_filename fiunction
   * enable printk.
   */
	 
  /* wrapfs_decode_filename(encoded_name,enc_len,key);
   */	

 out:
  if (crypted_name)
    kfree(crypted_name);
  if (encoded_name)
    kfree(encoded_name);
  return encoded_length;
}


void BF_cfb64_encrypt(unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec,  int *num, int encrypt)
{
  register BF_LONG v0, v1, t;
  register int n = *num;
  register long l = length;
  BF_LONG ti[2];
  unsigned char *iv, c, cc;
 
  iv = (unsigned char *) ivec;
  if (encrypt) {
    while (l--) {
      if (n == 0) {
	n2l(iv, v0);
	ti[0] = v0;
	n2l(iv, v1);
	ti[1] = v1;
	BF_encrypt((BF_LONG *) ti, schedule, BF_ENCRYPT);
	iv = (unsigned char *) ivec;
	t = ti[0];
	l2n(t, iv);
	t = ti[1];
	l2n(t, iv);
	iv = (unsigned char *) ivec;
      }
      c = *(in++) ^ iv[n];
      *(out++) = c;
      iv[n] = c;
      n = (n + 1) & 0x07;
    }
  } else {
    while (l--) {
      if (n == 0) {
	n2l(iv, v0);
	ti[0] = v0;
	n2l(iv, v1);
	ti[1] = v1;
	BF_encrypt((BF_LONG *) ti, schedule, BF_ENCRYPT);
	iv = (unsigned char *) ivec;
	t = ti[0];
	l2n(t, iv);
	t = ti[1];
	l2n(t, iv);
	iv = (unsigned char *) ivec;
      }
      cc = *(in++);
      c = iv[n];
      iv[n] = cc;
      *(out++) = c ^ cc;
      n = (n + 1) & 0x07;
    }
  }
  v0 = v1 = ti[0] = ti[1] = t = c = cc = 0;
  *num = n;
}

void BF_encrypt(BF_LONG *data,BF_KEY *key,int encrypt)
{
  register BF_LONG l, r, *p, *s;
 
  p = key->P;
  s = &(key->S[0]);
  l = data[0];
  r = data[1];
 
  if (encrypt) {
    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
#if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);
#endif
    r ^= p[BF_ROUNDS + 1];
  } else {
    l ^= p[BF_ROUNDS + 1];
#if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[20]);
    BF_ENC(l, r, s, p[19]);
    BF_ENC(r, l, s, p[18]);
    BF_ENC(l, r, s, p[17]);
#endif
    BF_ENC(r, l, s, p[16]);
    BF_ENC(l, r, s, p[15]);
    BF_ENC(r, l, s, p[14]);
    BF_ENC(l, r, s, p[13]);
    BF_ENC(r, l, s, p[12]);
    BF_ENC(l, r, s, p[11]);
    BF_ENC(r, l, s, p[10]);
    BF_ENC(l, r, s, p[9]);
    BF_ENC(r, l, s, p[8]);
    BF_ENC(l, r, s, p[7]);
    BF_ENC(r, l, s, p[6]);
    BF_ENC(l, r, s, p[5]);
    BF_ENC(r, l, s, p[4]);
    BF_ENC(l, r, s, p[3]);
    BF_ENC(r, l, s, p[2]);
    BF_ENC(l, r, s, p[1]);
    r ^= p[0];
  }
  data[1] = l & 0xffffffffL;
  data[0] = r & 0xffffffffL;
}
 
int wrapfs_decode_filename(const char *name,int length,char *key)
{
  int n, i, j, saved_length, saved_csum, csum;
  int uudecoded_length, error = 0;
  unsigned char iv[8];
  char *uudecoded_name,*decrypted_name=NULL;
    
  if (key == NULL) {
    error = -EACCES;
    goto out;
  }
  uudecoded_length = ((length + 3) / 4) * 3;
  if (uudecoded_length > MAXPATHLEN) { /* check for corruption */
    error = -ENAMETOOLONG;
    goto out;
  }
  uudecoded_name = kmalloc(uudecoded_length,GFP_KERNEL);
  if (!uudecoded_name) {
    error = -ENOMEM;
    goto out;
  }
 
  for (i = 0, j = 0; i < length; i += 4, j += 3) {
    uudecoded_name[j] = ((name[i] - 48) <<2) | ((name[i + 1] - 48) >>4);
    uudecoded_name[j + 1] = (((name[i + 1] - 48) <<4) & 240) | ((name[i + 2] - 48) >>2);
    uudecoded_name[j + 2] = (((name[i + 2] - 48) <<6) & 192) | ((name[i + 3] - 48) &63);
  }
  saved_csum = *(short *) uudecoded_name;
  saved_length = uudecoded_name[2];
	 
  if ((saved_length<1) || (saved_length+1 > MAXPATHLEN)) { /* check for corruption */
    error = -ENAMETOOLONG;
    goto out_free;
  }
 
  if (saved_length > uudecoded_length) {
    printk("Problems with the length - too big: %d", saved_length);
    error = -EACCES;
    goto out_free;
  }
 
  decrypted_name = (char *)kmalloc(saved_length+1, GFP_KERNEL); /* +1 for null */
  if (!decrypted_name) {
    error = -ENOMEM;
    goto out_free;
  }
  (decrypted_name)[saved_length] = '\0'; /* null terminate */
  memcpy(iv, global_iv, 8);
  n = 0;
  BF_cfb64_encrypt(uudecoded_name + 3,decrypted_name,
		   saved_length, (BF_KEY *) key, iv, &n,
		   BF_DECRYPT);
  for (csum = 0, i = 0; i < saved_length; i++)
    csum += (decrypted_name)[i];
  if (csum != saved_csum) {
    printk("Checksum error\n");
    kfree(decrypted_name);
    error = -EACCES;
    goto out_free;
  }
	
  /* Enable this printk to see decrypted name as we didn't implemented 
   * in the wrapfs functions
   */
	 
  /* printk("DECRYPTED NAME IS %s\n",decrypted_name); */
     
  error = saved_length + 1;
 out_free:
  kfree(uudecoded_name);
 out:
  return error;
}

#endif 
