#include <pcap/pcap.h>
#include <arpa/inet.h>
#include<netinet/tcp.h>
#include "decodificadores.h"

void TCPdecoder(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;

    /*struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;*/

    struct tcphdr *tcph=(struct tcphdr*)(Buffer);

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    printf("\n\n***********************TCP Packet*************************\n");

    //print_ip_header(Buffer,Size);

    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    //printf("                        DATA Dump                         ");
    printf("\n");

    /*printf(logfile , "IP Header\n");
    //PrintData(Buffer,iphdrlen);

    printf(logfile , "TCP Header\n");
    //PrintData(Buffer+iphdrlen,tcph->doff*4);

    printf("Data Payload\n");*/
    //PrintData(Buffer + header_size , Size - header_size );

    printf("\n###########################################################\n");
}
