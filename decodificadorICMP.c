#include <pcap/pcap.h>
#include <arpa/inet.h>
#include<netinet/ip_icmp.h>


void ICMPdecoder(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;

    /*struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;*/

    struct icmphdr *icmph = (struct icmphdr *)(Buffer);

    //int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    printf("\n\n***********************ICMP Packet*************************\n");

    //print_ip_header(Buffer , Size);

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
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");
 /*
    printf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);

    printf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);

    printf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
    */
    printf("\n###########################################################\n");
}
