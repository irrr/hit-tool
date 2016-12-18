
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "code2x.h"

///
///	File:	hexs2std.h: 把十六进制字符数组按8字节补全的实现
///

/*
*功能:把十六进制字符数组按8字节padding补全
*参数：src:源十六进制字符串
*返回：返回一个指向目的数组的指针
*/
char *hexs_to_std(const char *src)
{
	if (src == NULL)
	{
		return NULL;
	}

	int len = 0, slen = 0;	//nlen:源长度 len：填充后标准长度
	char *stdsrc = NULL, ch = '\0', *srcasc = NULL, *stdhex = NULL;

	srcasc = hexs_to_ascs(src);
	slen = strlen(srcasc);
	
	len = (slen / 8 + (slen % 8 ? 1 : 0)) * 8;
	
	stdsrc = (char *)malloc(sizeof(char) * len);
	if (stdsrc == NULL)
	{
		return NULL;
	}

	memcpy(stdsrc, srcasc, len);
	
	ch = 8 - slen % 8;	//padding 补齐方式

	memset(stdsrc + slen, ch, 8 - slen % 8);
	stdsrc[len] = '\0';
	

	stdhex = ascs_to_hexs(stdsrc);

	free(srcasc);
	free(stdsrc);
	
	return stdhex;

}
