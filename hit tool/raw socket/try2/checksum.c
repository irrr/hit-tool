in_cksum(unsigned short *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr; //u_short 16bit 
    register int sum = 0;
    u_short answer =0;
    while (nleft >1)
    {
        sum += *w++;
        nleft -= 2;  //16bit=2 bytes
    }
    if (nleft == 1)   //odd时，pad zero
    {
       *(u_char *)(&answer) = *(u_char *)w;
       sum += answer;
    }
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;   //求反
    return(answer);
}
 
/* calculate the ip checksum */
send_tcp.ip.check = 0;   //先检验和置0
send_tcp.ip.check=in_cksum((unsigned short *)&send_tcp.ip, 20);
 
/* calculate the tcp checksum */
struct pseudo_header //tcp伪头部
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length; //以上3＊32字节为伪造的tcp首部
    struct tcphdr tcp;  //TCP头
    u_char html[bufsize];  //html数据，包括http头和数据
} pseudo_header;
/* set the pseudo header fields */
pseudo_header.source_address = send_tcp.ip.saddr;
pseudo_header.dest_address = send_tcp.ip.daddr;
pseudo_header.placeholder = 0;
pseudo_header.protocol = IPPROTO_TCP;
pseudo_header.tcp_length = htons(20);
bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
//将send_tcp的数据拷如pseudo_header中的tcp
bcopy(htmlbuf, (char *)&pseudo_header.html, sizeof(htmlbuf));
send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, sizeof
(pseudo_header));
