#include "../des/code2x.h"
#include "../des/hexstok.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


//16位数据长度
#define DATA_16_LEN 2
//盐信息长度
#define MIX_DATA_LEN 10
//ip首部长度
#define IP_HEADER_LEN sizeof(struct ip)
//tcp首部长度
#define TCP_HEADER_LEN sizeof(struct tcphdr)
//ip首部 + tcp首部长度
#define IP_TCP_HEADER_LEN IP_HEADER_LEN + TCP_HEADER_LEN
//接收数据缓冲大小
#define BUFFER_SIZE 2048
//ip首部 + tcp首部 + 数据缓冲区大小
#define IP_TCP_BUFF_SIZE IP_TCP_HEADER_LEN + BUFFER_SIZE

struct hdata
{
	int frag_id;
	unsigned int t_data;               //填充于tcp seq位的信息，必须为32位，不足用0填充
	char m_data[MIX_DATA_LEN];                 //附加于ip tcp首部后面的迷惑信息
};                                     //隐蔽信息结构体

typedef struct hdata h_data;
typedef struct ip iphd;
typedef struct tcphdr tcphd;

struct pseudohdr
{
    struct in_addr saddr;
    struct in_addr daddr;
    u_char zero;
    u_char protocol;
    u_short length;
    struct tcphdr tcpheader;
}pseudoheader; //计算TCP校验和字段时需要加上伪首部

////////////////////////////////////////////////////////////////////
void err_exit(const char *err_msg);
void init_hdata(const char *data, h_data *hdata, int id);

iphd *init_ip_header(const char *src_ip, const char *dst_ip);
void fill_ip_header(iphd *ip_header, int ip_packet_len, int id);

tcphd *init_tcp_header(int src_port, int dst_port);
void fill_tcp_header(iphd *iphdr, tcphd *tcp_header, char *data);

void send_msg(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *data);
u_short checksum(u_short *data, u_short length);
////////////////////////////////////////////////////////////////////


//error handle
void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

// checksum
u_short checksum(u_short *data, u_short length)
{
    register long value;
    u_short i;
    for(i = 0; i < (length >> 1); i++)
    {
        value += data[i];
    }
    if(1 == (length &1))
    {
        value += (data[i] << 8);
    }
    value = (value & 65535) + (value >> 16);
    return (~value);
}


void init_hdata(const char *data, h_data *hdata, int id)
{
	char mix_data[MIX_DATA_LEN];

	int time = rand() % MIX_DATA_LEN;

	for (int i = 0; i < time; i++)
	{
		mix_data[i] = rand() % 95 + 32;  //产生32-127的随机数
	}
	mix_data[time] = '\0';

	hdata -> t_data = strtol(data, NULL, 16);
	strncpy(hdata -> m_data, mix_data, time + 1);
	hdata -> frag_id = id;

}

//ip首部
iphd *init_ip_header(const char *src_ip, const char *dst_ip)
{
    iphd *ip_header;

    ip_header = (iphd *)malloc(IP_HEADER_LEN);

    if(ip_header == NULL)
    {
    	return NULL;
    }

	bzero(ip_header, IP_HEADER_LEN);

    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = IP_HEADER_LEN / 4;        ///ip首部长度是指占多个32位的数量，4字节=32位，所以除以4
    ip_header->ip_tos = 0;
    ip_header->ip_len = 0;        //整个IP数据报长度，包括包头后面的数据
	ip_header->ip_id = 0;
    ip_header->ip_off = 0;							//默认DF==1,不分片
    ip_header->ip_ttl = MAXTTL;
    ip_header->ip_p = IPPROTO_TCP;                   //ip包封装的协议类型
    ip_header->ip_src.s_addr = inet_addr(src_ip);    //伪造的源IP地址
    ip_header->ip_dst.s_addr = inet_addr(dst_ip);    //目标IP地址
    ip_header->ip_sum = 0;
    return ip_header;
}

void fill_ip_header(iphd *ip_header, int ip_packet_len, int id)
{
	ip_header->ip_len = ip_packet_len;        //整个IP数据报长度，包括包头后面的数据
	ip_header->ip_id = id;                           //填充要发送的数据分片的序号
}

/* 构造tcp首部 */
tcphd *init_tcp_header(int src_port, int dst_port)
{
    tcphd *tcp_header;

    tcp_header = (tcphd *)malloc(TCP_HEADER_LEN);

    if(tcp_header == NULL)
    {
    	return NULL;
    }

    bzero(tcp_header, TCP_HEADER_LEN);

    tcp_header->source = htons(src_port);   //伪造的端口号
    tcp_header->dest = htons(dst_port);
    tcp_header->doff = sizeof(tcphd) / 4;  //同IP首部一样，这里是占32位的字节多少个
    tcp_header->seq = 0;
    tcp_header->syn = 0;
    tcp_header->check = 0;

    return tcp_header;
}

void fill_tcp_header(iphd *iphdr, tcphd *tcp_header, char *data)
{
	tcp_header->seq = strtol(data, NULL, 16); //填充隐蔽信息

	//填充伪首部信息， 用于计算tcp首部校验和
    memset(&pseudoheader, 0, 12 + TCP_HEADER_LEN);
    
	pseudoheader.saddr.s_addr = iphdr->ip_src.s_addr; // 伪造的源IP地址
	pseudoheader.daddr.s_addr = iphdr->ip_dst.s_addr; // 目的IP地址
	pseudoheader.protocol = IPPROTO_TCP;
	pseudoheader.length = htons(TCP_HEADER_LEN);
	bcopy((char *)tcp_header, (char *)&pseudoheader.tcpheader, TCP_HEADER_LEN);

	tcp_header->check = checksum((u_short *)&pseudoheader, 12 + TCP_HEADER_LEN);   //填充校验和字段
}

/* 发送构造的隐蔽信息报文 */
void send_msg(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *data)
{
///////////////////////////////////////////////////////////////////////
    iphd *ip_header;
    tcphd *tcp_header;	//tcp header
    struct sockaddr_in dst_addr;
    char *frag = NULL;
    h_data hdata;
    int failed = 0, i = 1;

    socklen_t sock_addrlen = sizeof(struct sockaddr_in);

    
    int ip_packet_len;                //总的数据包首部+数据的长度
    ip_packet_len = IP_TCP_HEADER_LEN + MIX_DATA_LEN;
    char buf[ip_packet_len];

    int sockfd, ret_len, on = 1, id = 0;  //id用于信息分割后的分片重组，填充在ip首部的id位
    char *hexstr = NULL;                 
    
    memset(&dst_addr, 0, sock_addrlen);
    dst_addr.sin_family = PF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    dst_addr.sin_port = htons(dst_port);

    /* 创建tcp原始套接字 */
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        err_exit("socket()");
    }

    /* 开启IP_HDRINCL，自定义IP首部 */
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
    {
        err_exit("setsockopt()");
    }


    /* ip首部 */
    ip_header = init_ip_header(src_ip, dst_ip);

    if(ip_header == NULL)
    {
    	err_exit("ip_header()");
    }
    /* tcp首部 */
    tcp_header = init_tcp_header(src_port, dst_port);

    if(tcp_header == NULL)
    {
    	err_exit("tcp_header()");
    }

    bzero(buf, ip_packet_len);
    memcpy(buf, ip_header, IP_HEADER_LEN);
    memcpy(buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
////////////////////////////////////////////////////////////////////////
    hexstr = ascs_to_hexs(data);
    while(hexstok(hexstr, i ,8) != NULL)
	{

		frag = hexstok(hexstr, i, 8);

		init_hdata(frag, &hdata, id++);

		fill_ip_header(ip_header, ip_packet_len, hdata.frag_id);
		fill_tcp_header(ip_header, tcp_header, frag);

		memcpy(buf + IP_TCP_HEADER_LEN, hdata.m_data, MIX_DATA_LEN);
		/* 发送报文 */
		ret_len = sendto(sockfd, buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
		if (ret_len > 0)
		{
			printf("Frag %d sendto() ok!!!\n", hdata.frag_id);
            printf("%d %s\n", hdata.t_data, hdata.m_data);
		}
		else 
		{
			printf("Frag %d sendto() failed\n", hdata.frag_id);
			failed = 1;
		}

		i+=8;
		free(frag);
	}

	if(!failed)
	{
		printf("All frag sendto() ok!!!\n");
	}
	else 
	{
		err_exit("sendto()");
	}





    // char buff[IP_TCP_BUFF_SIZE];
    // while (1)
    // {
    //     bzero(buff, IP_TCP_BUFF_SIZE);
    //     ret_len = recv(sockfd, buff, IP_TCP_BUFF_SIZE, 0);
    //     if (ret_len > 0)
    //     {
    //         /* 取出ip首部 */
    //         ip_header = (struct ip *)buff;
    //         /* 取出tcp首部 */
    //         tcp_header = (struct tcphdr *)(buff + IP_HEADER_LEN);
    //         printf("=======================================\n");
    //         printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
    //         printf("from port:%d\n", ntohs(tcp_header->source));
    //         /* 取出数据 */
	   //  printf("the result is %s\n",buff + IP_TCP_HEADER_LEN);

    //     }
    // }
    close(sockfd);

    free(hexstr);
    free(ip_header);
    free(tcp_header);
}

int main(int argc, const char *argv[])
{
    if (argc != 6)
    {
        printf("usage:%s src_ip src_port dst_ip dst_port data\n", argv[0]);
        exit(1);
    }
    srand((unsigned)time(0)); //用时间做种，每次产生随机数不一样
    /* 发送ip_tcp报文 */
    send_msg(argv[1], atoi(argv[2]), argv[3], atoi(argv[4]), argv[5]);
    
    return 0;
}
