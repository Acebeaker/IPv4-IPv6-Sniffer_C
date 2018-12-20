//#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include </usr/include/netinet/ip6.h>
#include "decodificadores.h"


void print_ipv6();

char sourIP6[40];
char destIP6[40];

void ip6Decoder (const u_char *bytes, bpf_u_int32 dataLength){

    FILE *Register;
    Register = fopen ( "registroTrafico.csv", "a" );


    printf("\n***************************** IPv6 *****************************\n\n");
    struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(bytes);
    bzero(sourIP6,sizeof(sourIP6));
    bzero(destIP6,sizeof(destIP6));
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), sourIP6, INET6_ADDRSTRLEN);
  	inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);

  	int nextheader = ipv6_header->ip6_nxt;

    printf("\n");
    printf("Ether Type: IPv6 \n");
    printf("Source Address: %s \n", sourIP6);
    printf("Destination Address: %s \n", destIP6);

    fprintf(Register, "%s;", sourIP6);
    fclose(Register);
    switch(nextheader){
      	//TCP
      	case IPPROTO_TCP:
          TCPdecoder(bytes + sizeof(*ipv6_header), dataLength - sizeof(*ipv6_header));
      		break;
      	//UDP
      	case IPPROTO_UDP:
          UDPdecoder(bytes + sizeof(*ipv6_header), dataLength - sizeof(*ipv6_header));
      		break;
      	//ICMPv6
      	case IPPROTO_ICMPV6:
          ICMPv6decoder(bytes + sizeof(*ipv6_header), dataLength - sizeof(*ipv6_header));
      		break;
        }
}

void print_ipv6()
{
    printf("\n");
    printf("Ether Type: IPv6 \n");
    printf("Source Address: %s \n", sourIP6);
    printf("Destination Address: %s \n", destIP6);
    //printf("Extension Headers:");
}
