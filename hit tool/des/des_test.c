#include "des.h"
#include "hexstok.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//
//    gcc -Wall -O2 -o des_tok des.c hexs2std.c code2x.c hexstok.c -lcrypto
//
int main()
{
	char *str = "I love China very much!";
	char *key = "abcdefg";
	char *ds = NULL;
	char *hh = NULL;
	char *hexstr = NULL;
	int i = 1;

	printf("before encrypt: %s %s\n", ascs_to_hexs(str), str);
	hh = DES_encrypt(str, key);
	
	printf("after encrypto: %s %s\n", ascs_to_hexs(hh), hh);
	hh = DES_decrypt(hh, key);

	printf("after decrypto: %s %s\n" ,ascs_to_hexs(hh), hh);

	hexstr = ascs_to_hexs(hh);

	while(hexstok(hexstr, i ,4) != NULL)
	{
		ds = hexstok(hexstr, i, 4);
		printf("%s\n", ds);
		i+=4;
	}

	free(hh);
	free(hexstr);
	free(ds);

	
	return 0;
}
