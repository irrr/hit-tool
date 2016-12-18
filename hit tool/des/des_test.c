#include "des.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//
//    gcc -Wall -O2 -o openssl_des openssl_des.c hexs2std.c code2x.c -lcrypto
//
int main()
{
	char *str = "lov";
	char *key = "abcdefg";
	
	char *hh = NULL;
	
	printf("before encrypt: %s %s\n", ascs_to_hexs(str), str);
	hh = DES_encrypt(str, key);
	
	printf("after encrypto: %s %s\n", ascs_to_hexs(hh), hh);
	hh = DES_decrypt(hh, key);

	printf("after decrypto: %s %s\n" ,ascs_to_hexs(hh), hh);
	
	free(hh);

	
	return 0;
}