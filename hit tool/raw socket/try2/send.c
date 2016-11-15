#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//16位数据长度
#define DATA_16_LEN 2
//盐信息长度
#define MIX_DATA_LEN 20
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

typedef struct
{
	int frag_id;
	char f_data[DATA_16_LEN];                   //填充于tcp seq低位的迷惑信息，必须为16位，不足用0填充
    char t_data[DATA_16_LEN];                  //填充于tcp seq高位的真实信息，必须为16位，不足用0填充
    char m_data[MIX_DATA_LEN];                 //附加于ip tcp首部后面的迷惑信息
}scr_data;                                    //隐蔽信息结构体


typedef struct ip iphd;
typedef struct tcphdr tcphd;

void init_srcdata(const char *src_data, scr_data *scrdata, int id);

void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

struct pseudohdr
{
    struct in_addr saddr;
    struct in_addr daddr;
    u_char zero;
    u_char protocol;
    u_short length;
    struct tcphdr tcpheader;
}pseudoheader; //计算TCP校验和字段时需要加上伪首部

//构造ip首部
iphdr *creat_ip_header(const char *src_ip, const char *dst_ip, int ip_packet_len, int id)
{
    iphd *ip_header;

    ip_header = (iphdr *)malloc(IP_HEADER_LEN);
    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = sizeof(iphd) / 4;        ///ip首部长度是指占多个32位的数量，4字节=32位，所以除以4
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(ip_packet_len);        //整个IP数据报长度，包括包头后面的数据
    ip_header->ip_id = id;                           //填充要发送的数据分片的序号
    ip_header->ip_off = 0;							//默认DF==1,不分片
    ip_header->ip_ttl = MAXTTL;
    ip_header->ip_p = IPPROTO_TCP;                   //ip包封装的协议类型
    ip_header->ip_src.s_addr = inet_addr(src_ip);    //伪造的源IP地址
    ip_header->ip_dst.s_addr = inet_addr(dst_ip);    //目标IP地址
    
    ip_header->ip_sum = checksum((u_short *)ip_header, sizeof(iphd));                           //最后计算校验和 

    return ip_header;
}

/* 构造tcp首部 */
tcphdr *creat_tcp_header(iphd *iphdr, int src_port, int dst_port, char *data)
{
    tcphd *tcp_header;

    tcp_header = (tcphd *)malloc(TCP_HEADER_LEN);
    tcp_header->source = htons(src_port);   //伪造的端口号
    tcp_header->dest = htons(dst_port);
    tcp_header->doff = sizeof(tcphd) / 4;  //同IP首部一样，这里是占32位的字节多少个
    
    tcp_header->seq = atoi(data); //填充隐蔽信息
    
    //填充伪首部信息， 用于计算tcp首部校验和
    memset(&pseudoheader, 0, 12 + sizeof(tcphd));
    
	pseudoheader.saddr.s_addr = iphdr->ip_src.s_addr; // 伪造的源IP地址
	pseudoheader.daddr.s_addr = ip_dst.s_addr; // 目的IP地址
	pseudoheader.protocol = IPPROTO_TCP;
	pseudoheader.length = htons(sizeof(tcphd));
	bcopy((char *)tcpheader, (char *)&pseudoheader.tcpheader, sizeof(tcphd));
    
    //发起连接
    tcp_header->syn = 1;
    tcp_header->window = 4096;
    tcp_header->check = checksum((u_short *)&pseudoheader, 12 + sizeof(tcphd));   //填充校验和字段

    return tcp_header;
}

/* 发送构造的隐蔽信息报文 */
void send_scr_msg(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *data)
{
    iphd *ip_header;
    tcphd *tcp_header;
    struct sockaddr_in dst_addr;
    
    socklen_t sock_addrlen = sizeof(struct sockaddr_in);
    
    scr_data srcdata;
    
    int ip_packet_len;                //总的数据包首部+数据的长度
    char buf[ip_packet_len];
    int sockfd, ret_len, on = 1, id = 0;  //id用于信息分割后的分片重组，填充在ip首部的id位
    char send_buff[4];                 //分片后每次要发送的数据，为f_data + t_data, 所以肯定是32位
    
    memset(mix_data, 0 , sizeof(char)*20);
    
    mix_data_len = strlen(mix_data);
    ip_packet_len = IP_TCP_HEADER_LEN + data_len;

    memset(&dst_addr, 0, sock_addrlen);
    dst_addr.sin_family = PF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    dst_addr.sin_port = htons(dst_port);

    /* 创建tcp原始套接字 */
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        err_exit("socket()");

    /* 开启IP_HDRINCL，自定义IP首部 */
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
        err_exit("setsockopt()");

    /* ip首部 */
    ip_header = fill_ip_header(src_ip, dst_ip, ip_packet_len, id++);
    /* tcp首部 */
    tcp_header = fill_tcp_header(src_port, dst_port, send_buff);

    bzero(buf, ip_packet_len);
    memcpy(buf, ip_header, IP_HEADER_LEN);
    memcpy(buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
    memcpy(buf + IP_TCP_HEADER_LEN, data, data_len);

    /* 发送报文 */
    ret_len = sendto(sockfd, buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
    if (ret_len > 0)
        printf("sendto() ok!!!\n");
    else printf("sendto() failed\n");

    char buff[IP_TCP_BUFF_SIZE];
    while (1)
    {
        bzero(buff, IP_TCP_BUFF_SIZE);
        ret_len = recv(sockfd, buff, IP_TCP_BUFF_SIZE, 0);
        if (ret_len > 0)
        {
            /* 取出ip首部 */
            ip_header = (struct ip *)buff;
            /* 取出tcp首部 */
            tcp_header = (struct tcphdr *)(buff + IP_HEADER_LEN);
            printf("=======================================\n");
            printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
            printf("from port:%d\n", ntohs(tcp_header->source));
            /* 取出数据 */
	    printf("the result is %s\n",buff + IP_TCP_HEADER_LEN);

        }
    }
    close(sockfd);
    free(ip_header);
    free(tcp_header);
}

// checksum()定义
u_short checksum(u_short *data, u_short length)
{
    register long value;
    u_short i;
    for(int i = 0; i < (length >> 1); i++)
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

int main(int argc, const char *argv[])
{
    if (argc != 7)
    {
        printf("usage:%s src_ip src_port dst_ip dst_port firstint lastint\n", argv[0]);
        exit(1);
    }

    /* 发送ip_tcp报文 */
    ip_tcp_send(argv[1], atoi(argv[2]), argv[3], atoi(argv[4]), argv[5] ,argv[6]);
    
    return 0;
}
