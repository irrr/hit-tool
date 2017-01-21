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

#define PORT 8888

#define SOURCEADDR "127.0.0.1"

#define DESADDR "127.0.0.1"

#define MAXDATASIZE 100


int main()

{

int sockfd,num;

struct sockaddr_in addr,peer;

int on;

on = 1;

int mm;

char buf[MAXDATASIZE];

int peerlen = sizeof(peer);

char *shuju;

int nn;

/*创建一个TCP的原始套接字*/

if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP))==-1)

{

perror("socket() error.");

exit(1);

}

/*设置IP_HDRINCL选项,以便构造自己的IP头部*/

setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));

char buffer[100];

struct ip *ip;

struct tcphdr *tcp;

int head_len;

int i;

head_len = sizeof(struct ip) + sizeof(struct tcphdr);

/*初始化缓冲区*/

bzero(buffer,100);

/*初始化IP头部*/

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

ip->ip_dst.s_addr = inet_addr(SOURCEADDR);

ip->ip_src.s_addr = inet_addr(SOURCEADDR);

/*初始化TCP头部*/

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

/*接收客户端发来的数据*/

while(1)

{

if((num = recvfrom(sockfd,buffer,MAXDATASIZE,0,(struct sockaddr *)&peer,&peerlen)) == -1)
{

printf("recvfrom() error\n");

exit(1);

}

/*输出客户端的数据*/
const char *split = ","; //分隔符可以定义多个
char *numble;
int res = 0;
numble = strtok(shuju, split);
while (numble != NULL ) {
res += atoi(numble);
numble = strtok(NULL , split);
}

printf("The result is: %d\n",res);

//
char sendBuffer[100];

bzero(sendBuffer,100);

/*初始化IP头部*/

ip = (struct ip *)sendBuffer;

ip->ip_v = IPVERSION;

ip->ip_hl = sizeof(struct ip) >> 2;

ip->ip_tos = 0;

ip->ip_len = htons(head_len);

ip->ip_id = 0;

ip->ip_off = 0;

ip->ip_ttl = MAXTTL;

ip->ip_p = IPPROTO_TCP;

ip->ip_sum = 0;

ip->ip_dst = peer.sin_addr;

ip->ip_src.s_addr = inet_addr(SOURCEADDR);

/*初始化TCP头部*/

tcp = (struct tcphdr *)(sendBuffer + sizeof(struct ip));

tcp->source = htons(PORT);

tcp->dest = htons(PORT);

tcp->seq = random();

tcp->ack_seq = 0;

tcp->doff = 5;

tcp->psh = 1;

tcp->check = 0;

/*让shuju指针指向数据存储处*/

shuju =&sendBuffer[sizeof(struct ip) + sizeof( struct tcphdr)];

char resBuffer[10];

bzero(resBuffer,10);

sprintf(resBuffer, "%d", res);

memcpy(shuju,resBuffer,strlen(resBuffer));

head_len = sizeof(struct ip) + sizeof(struct tcphdr) + strlen(resBuffer);

if((num=sendto(sockfd,shuju,head_len,0,(struct sockaddr *)&peer,sizeof(struct sockaddr)))==-1){

printf("send wrong\n");

}

}

/*关闭套接字*/

close(sockfd);

}
