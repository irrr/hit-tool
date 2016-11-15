#include<stdio.h>

#include<netinet/tcp.h>

#include<netinet/ip.h>

#include<unistd.h>

#include<sys/types.h>

#include<sys/socket.h>

#include<netinet/in.h>

#include<arpa/inet.h>

#include<stdlib.h>

#include<netinet/udp.h>

#include <string.h>

#define PORT  8888

#define SOURCEADDR "127.0.0.1"

#define MAXDATASIZE 100

#define DESADDR "127.0.0.1"

int main(int argc,char *argv[])

{

int sockfd,num;

struct sockaddr_in addr,peer;

int on;

on = 1;

int mm;

char buf[MAXDATASIZE];

int peerlen = sizeof(peer);

char msg[20];

strcat(msg,argv[1]);
strcat(msg,",");
strcat(msg,argv[2]);

int msglen = strlen(msg);

char * shuju;

int nn;

if(argc !=3)

{

printf("Usage:%s<firstnumble,lastnumble>\n",argv[0]);

exit(1);

}

bzero(&addr,sizeof(struct sockaddr_in));

addr.sin_family=AF_INET;

addr.sin_port=htons(PORT);

inet_aton(DESADDR,&addr.sin_addr);

/*创建套接字*/

if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP))==-1)

{

perror("socket() error.");

exit(1);

}

/*设置IP_HDRINCL选项,构造自己的IP头部*/

setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));

char buffer[100];

struct ip *ip;

struct tcphdr *tcp;

int head_len;

int i;

head_len = sizeof(struct ip) + sizeof(struct tcphdr) + msglen;

bzero(buffer,100);

/*初始化IP的头部*/

ip = (struct ip *)buffer;

ip->ip_v = IPVERSION;

ip->ip_hl = sizeof(struct ip) >> 2;

ip->ip_tos = 0;

ip->ip_len = htons(head_len);

ip->ip_id = 0;

ip->ip_off = 0;

ip->ip_ttl = MAXTTL;

ip->ip_p = IPPROTO_TCP;

ip->ip_sum = 0;

ip->ip_dst =  addr.sin_addr;

ip->ip_src.s_addr = inet_addr(SOURCEADDR);

printf("dest address is %s\n",inet_ntoa(addr.sin_addr));

/*初始化TCP的头部*/

tcp = (struct tcphdr *)(buffer + sizeof(struct ip));

tcp->source = htons(PORT);

tcp->dest = htons(PORT);

tcp->seq = random();

tcp->ack_seq = 0;

tcp->doff = 5;

tcp->psh = 1;

tcp->check = 0;

/*让shuju指针指向数据存储处*/

shuju =&buffer[sizeof(struct ip) + sizeof( struct tcphdr)];

memcpy(shuju,msg,msglen);

/* 发送数据*/

mm = sendto(sockfd,buffer,head_len,0,(struct sockaddr *)&addr,sizeof(struct sockaddr));

//
/*接收客户端发来的数据*/

while(1)

{

if((num = recvfrom(sockfd,buffer,200,0,(struct sockaddr *)&peer,&peerlen)) == -1)
{

printf("recvfrom() error\n");

exit(1);

}

printf("result is %s\n",shuju);

}
close(sockfd);

}
