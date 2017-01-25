#include "../des/code2x.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* ip首部长度 */
#define IP_HEADER_LEN sizeof(struct ip)
/* tcp首部长度 */
#define TCP_HEADER_LEN sizeof(struct tcphdr)
/* ip首部 + tcp首部长度 */
#define IP_TCP_HEADER_LEN IP_HEADER_LEN + TCP_HEADER_LEN
/* 数据缓冲大小 */
#define BUFFER_SIZE 140
/* ip首部 + tcp首部 + 数据缓冲区大小 */
#define IP_TCP_BUFF_SIZE IP_TCP_HEADER_LEN + BUFFER_SIZE * 10
#define FRAG_SIZE 9

typedef struct
{
	int frag_id;
	unsigned int data;
}datarray;

typedef struct ip iphd;
typedef struct tcphdr tcphd;


void err_exit(const char *err_msg);
void listen_msg();
void print_msg(const char *src_ip, datarray *data);
char *digit_to_hexs(const int num);

char *digit_to_hexs(const int num)
{
	char *hexstr = (char *)malloc(sizeof(char) * FRAG_SIZE);
	memset(hexstr, 0, FRAG_SIZE);

	snprintf(hexstr, FRAG_SIZE, "%x", num);

	return hexstr;
}


void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

void print_msg(const char *src_ip, datarray *data)
{
	char hex_msg[BUFFER_SIZE] = {0};
	char *tmp = NULL;
    char *t_msg = NULL;

	for(int i = 0; data[i].frag_id > 0; i++)
	{
		tmp = digit_to_hexs(data[i].data);
		strncat(hex_msg, tmp, strlen(tmp));
        free(tmp);
	}
    t_msg = hexs_to_ascs(hex_msg);
	printf("%s:%s\n",src_ip, t_msg);
    free(t_msg);
}

/* 原始套接字接收 */
void listen_msg()
{
    iphd *ip_header;
    tcphd *tcp_header;
    int recvfd, ret_len, i = 0;
    datarray data[BUFFER_SIZE / 4]={0};	//32bits == 4bytes 
    char src_ip[20];
    char buf[IP_TCP_BUFF_SIZE];

    if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        err_exit("socket()");
    }

    printf("Listen...\n");
    /* 接收数据 */
    while (1)
    {
        memset(buf, 0, IP_TCP_BUFF_SIZE);
        ret_len = recv(recvfd, buf, IP_TCP_BUFF_SIZE, 0);
        if (ret_len > 0)
        {
        	ip_header = (struct ip *)buf;
            /* 取出tcp首部 */
            tcp_header = (struct tcphdr *)(buf + IP_HEADER_LEN);

            if(ntohs(tcp_header->dest) == 6666)
            {
                if(tcp_header -> seq == 1)
                {
                    snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(ip_header -> ip_src));
                    print_msg(src_ip, data);
                    memset(data, 0, BUFFER_SIZE/4);
                    i = 0;
                }
                else
                {
                    data[i].frag_id = ip_header -> ip_id;
                    data[i].data = tcp_header -> seq;
                    i++;
                }

       //      	printf("=======================================\n");
       //      	printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
       //      	printf("from port:%d\n", ntohs(tcp_header->source));
	    		// printf("the ID is %d\n",ip_header->ip_id);
	    		// printf("the data is %d\n",tcp_header->seq);
	    		// printf("=======================================\n");
            }
        }
    }
    
    close(recvfd);
}

int main(void)
{
    /* 原始套接字接收 */
    listen_msg();

    return 0;
}
