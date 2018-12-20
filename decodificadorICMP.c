#include <pcap/pcap.h>
#include <arpa/inet.h>
#include<netinet/ip_icmp.h>
#include "decodificadores.h"

void ICMPdecoder(const u_char * Buffer , int Size)
{

    unsigned short iphdrlen;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer);

    FILE *Register;
    Register = fopen ( "registroTrafico.csv", "a" );
    fprintf(Register, "ICMP;%ld;\n",Size - sizeof(*icmph));
    fclose(Register);
    printf("\n\n***********************ICMP Packet*************************\n");

    printf("\n");

    printf("ICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
    {
        printf("  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        printf("  (ICMP Echo Reply)\n");
    }

    printf("   |-Code : %d\n",(unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    printf("\n");
    
    printf("\n###########################################################\n");
}
