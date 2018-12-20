#include <pcap/pcap.h>
#include <arpa/inet.h>
#include<netinet/udp.h>
#include "decodificadores.h"

void UDPdecoder(const u_char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct udphdr *udph = (struct udphdr*)(Buffer);

    FILE *Register;
    Register = fopen ( "registroTrafico.csv", "a" );
    fprintf(Register, "UDP;%ld;\n",Size - sizeof(*udph) );
    fclose(Register);


    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    printf("\n\n***********************UDP Packet*************************\n");

    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    printf("\n");

    printf("\n###########################################################\n");
}
