#include <pcap/pcap.h>
#include <arpa/inet.h>
#include<netinet/udp.h>

void UDPdecoder(const u_char *Buffer , int Size)
{

    unsigned short iphdrlen;
/*
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;*/

    struct udphdr *udph = (struct udphdr*)(Buffer);

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    printf("\n\n***********************UDP Packet*************************\n");

    //print_ip_header(Buffer,Size);

    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    printf("\n");
  /*  printf(logfile , "IP Header\n");
    //PrintData(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    //PrintData(Buffer+iphdrlen , sizeof udph);

    printf(logfile , "Data Payload\n");
*/
    //Move the pointer ahead and reduce the size of string
    //PrintData(Buffer + header_size , Size - header_size);

    printf("\n###########################################################\n");
}
