#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include "decodificadores.h"

void ICMPv6decoder(const u_char *bytes, int size)
{
    printf("\n***************************** ICMPv6 *****************************\n\n");

    u_char *payload;
    int dataLength = 0;

    //get icmp6 header
    struct icmp6_hdr* header_icmp6 = (struct icmp6_hdr*)(bytes);

    //get and print out payload data



    printf("ICMPv6 Header\n");
    printf("   |-Type : %d",(unsigned int)(header_icmp6->icmp6_type));
    unsigned int tipo =(unsigned int)(header_icmp6->icmp6_type);
    switch (tipo) {
      case 1:
        printf("  Host Unreachable...\n");
        break;
      case 2:
        printf("  Packet To Big...\n");
        break;
      case 3:
        printf("  Time Exceeded...\n");
        break;
      case 4:
        printf("  Parameter Problem...\n");
        break;

    }

    printf("   |-Code : %d\n",(unsigned int)(header_icmp6->icmp6_code));
    printf("   |-Checksum : %d\n",ntohs(header_icmp6->icmp6_cksum));
}
