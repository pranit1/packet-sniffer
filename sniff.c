#include<stdio.h> 
#include<string.h> 
#include<stdlib.h> 
#include<errno.h> 
#include<netinet/tcp.h>	
#include<netinet/udp.h>	
#include<netinet/ip.h>	
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<unistd.h>
#include<sys/types.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>
#define MAXBUFF 65536

struct sockaddr source;
struct sockaddr_in souraddr,destaddr;
char buff[MAXBUFF];
int total=0;

void sniffer(char *buffer, int packet)
{
total++;
unsigned int iplen;
unsigned int protocol;
struct iphdr *ip=(struct iphdr*)(buffer+sizeof(struct ethhdr));
struct tcphdr *tcp=(struct tcphdr*)(buffer+sizeof(struct ethhdr)+iplen);
struct udphdr *udp=(struct udphdr*)(buffer+iplen+sizeof(struct ethhdr));
iplen=(ip->ihl)*4;

memset(&souraddr,0,sizeof(souraddr));
memset(&destaddr,0,sizeof(destaddr));
souraddr.sin_addr.s_addr=ip->saddr;
destaddr.sin_addr.s_addr=ip->daddr;

protocol=ip->protocol;
if(protocol==6 || protocol==17)
{

	printf("\n");
	printf("Total Packets:\t %d \n",total);
	printf("***************IP HEADER***************\n");
	printf("Version:		%d \n",(unsigned int)ip->version);
	printf("Header Length:		%d \n",(unsigned int)ip->ihl);
	printf("Type of Service:	%d\n",(unsigned int)ip->tos);
	printf("Total Length:		%d \n",ntohs(ip->tot_len));
	printf("Id:			%d \n",ntohs(ip->id));
	printf("TTL:			%d \n",(unsigned int)ip->ttl);
	printf("Protocol:		%d \n",(unsigned int)ip->protocol);
	printf("Checksum:		%d \n",(unsigned int)ip->check);
	printf("Source:			%s \n",inet_ntoa(souraddr.sin_addr));
	printf("Destination:		%s\n",inet_ntoa(destaddr.sin_addr));

}

if(protocol==6)
{
	printf("\n");
	printf("Total Packets:\t %d \n",total);
	printf("***************TCP HEADER***************\n");
	printf("Source Port: %u	| Destination Port: %u\n",ntohs(tcp->source),ntohs(tcp->dest));
	printf("Sequence Number: %u\n",ntohl(tcp->seq));
	printf("Acknowledgement: %u\n",ntohl(tcp->ack_seq));
	printf("Data Offset: %d |Flags:-URG: %d,ACK: %d,PSH: %d,RST: %d,SYN: %d,FIN: %d|Window: %d\n",(unsigned int)tcp->doff,(unsigned int)tcp->urg,(unsigned int)tcp->ack,(unsigned int)tcp->psh,(unsigned int)tcp->rst,(unsigned int)tcp->syn,(unsigned int)tcp->fin,ntohs(tcp->window));
	printf("Checksum: %d |Urgent Pointer: %d \n",ntohs(tcp->check),tcp->urg_ptr);

}

else if(protocol==17)
{
	printf("\n");
	printf("Total Packets:\t %d \n",total);
	printf("***************UDP HEADER***************\n");
	printf("Source Port: %d | Destination Port: %d \n",ntohs(udp->source),ntohs(udp->dest));
	printf("Length: %d \n",ntohs(udp->len));
	printf("Checksum: %d \n", ntohs(udp->check));

}

}



int main()
{

int sock,packet_data;
socklen_t source_len;
/*Create a socket*/
sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

if(sock<0)
{
	printf("error creating socket\n");
	exit(1);
}

while(1)
{
	source_len=sizeof(source);
	packet_data=recvfrom(sock,buff,MAXBUFF,0,&source,&source_len);
	if(packet_data<0)
	{
		perror("error: %s in recvfrom\n",gai_strerror(packet_data));
		return 1;
	}
	sniffer(buff,packet_data);
}

return 0;
}






