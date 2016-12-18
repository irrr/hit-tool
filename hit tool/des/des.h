#ifndef DES_H
#define DES_H
#include "hexs2std.h"
#include "code2x.h"
///
///	File:	des.h:  functions about des encrypt and decrypt
///
char *openssl_des(const char *src, const char *key, int enc); //main function
char *DES_encrypt(const char *src, const char *key); //encrypt function
char *DES_decrypt(const char *src, const char *key); //decrypt function

#endif // !DES_H