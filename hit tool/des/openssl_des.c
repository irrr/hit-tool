#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#include "hexs2std.h"
#include "code2x.h"

char *openssl_des(const char *src, const char *key, int enc);
char *DES_encrypt(const char *src, const char *key);
char *DES_decrypt(const char *src, const char *key);

char *DES_encrypt(const char *src, const char *key)
{
	char *hexs = NULL, *stdsrc = NULL, *dst = NULL, *stdhex = NULL;
	
	hexs = ascs_to_hexs(src);
	
	stdsrc = hexs_to_std(hexs);
	stdhex = ascs_to_hexs(stdsrc);
	dst = openssl_des(stdhex, key, DES_ENCRYPT);
	
	free(hexs);
	free(stdsrc);
	free(stdhex);
	
	return dst;
}

char *DES_decrypt(const char *src, const char *key)
{
	char *hexs = NULL, *stdsrc = NULL, *dst = NULL, *stdhex = NULL;
	
	hexs = ascs_to_hexs(src);
	
	stdsrc = hexs_to_std(hexs);
	
	stdhex = ascs_to_hexs(stdsrc);
	
	dst = openssl_des(stdhex, key, DES_DECRYPT);
	
	free(hexs);
	free(stdsrc);
	free(stdhex);
	
	return dst;
}

char *openssl_des(const char *src, const char *key, int enc)
{
	DES_key_schedule ks;
	DES_cblock ky;
	char *dst = NULL, out[8], *tmp = NULL, *stmp = NULL;
	int cunt = 0;
	
	tmp = (char *)malloc(sizeof(char) * 16);
	if(tmp == NULL)
	{
		return NULL;
	}
	
	cunt = strlen(src) / 16;
	//根据字符串生成key
	DES_string_to_key(key, &ky);
	
	//设置密码表
	DES_set_key_unchecked(&ky, &ks);
	
	dst = (char *)malloc(sizeof(char) * cunt * 8);
	if(dst == NULL)
	{
		return NULL;
	}
	
	if(enc == DES_ENCRYPT)
	{
		for(int i = 0; i < cunt; i++)
		{
			memcpy(tmp, src + i * 16, 16);
			tmp[16] = '\0';
			stmp = hexs_to_ascs(tmp);
			DES_ecb_encrypt((const_DES_cblock *)stmp, (DES_cblock *)out, &ks, DES_ENCRYPT);
			memcpy(dst + 8 * i, out, 8);
			free(stmp);
		}
		dst[cunt * 8] = '\0';
	}
	else
	{
		for(int i = 0; i < cunt; i++)
		{
			memcpy(tmp, src + i * 16, 16);
			tmp[16] = '\0';
			stmp = hexs_to_ascs(tmp);
			printf("%s\n", stmp);
			DES_ecb_encrypt((const_DES_cblock *)stmp, (DES_cblock *)out, &ks, DES_DECRYPT);
			memcpy(dst + 8 * i, out, 8);
			free(stmp);
		}
		dst[cunt * 8] = '\0';
	}
	free(tmp);
	
	return dst;
}


int main()
{
	char *str = "wheel";
	char *key = "abcdefg";
	
	char *hh = NULL;
	int len = 0;
	
	printf("加密前:%s\n", str);
	
	hh = DES_encrypt(str, key);
	len = strlen(hh);
	
	printf("%s\n", hh);

	
	free(hh);

	
	return 0;
}
	
		
	
