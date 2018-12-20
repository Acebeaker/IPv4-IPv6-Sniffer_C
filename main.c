#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "decodificadores.h"
//#include <netinet/ether.h>

/*#include <net/ethernet.h>
#include <netinet/ether.h>

#include <netinet/in.h>
#include <net/if_arp.h>

#include <netinet/ip.h>

#include </usr/include/netinet/ip6.h>

#include<netinet/tcp.h>

#include<netinet/udp.h>

#include<netinet/ip_icmp.h>

#include <netinet/icmp6.h>*/
//#include "decodificadorEthernet.c"
#define LENGTH_CAPTURE 2000



void pcap_handler_callback(u_char * arg, const struct pcap_pkthdr *h, const u_char *bytes);



int main(int argc, char **argv)
{
    FILE *Register;
	  Register = fopen ( "registroTrafico.csv", "w" );
    fprintf(Register, "Source Addres;Protocol;Data Length\n");
    fclose(Register);
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handleloop;
    handleloop = pcap_open_live("enp0s3",LENGTH_CAPTURE,1,1000,errbuff);
    if(handleloop == NULL){
        perror(errbuff);
        exit(EXIT_FAILURE);
    }
    printf("Empezando a capturar paquetes\n");
    pcap_loop(handleloop,-1,pcap_handler_callback,NULL);
}

void pcap_handler_callback(u_char * arg, const struct pcap_pkthdr *h, const u_char *bytes){
    printf("\nLongitud de la captura: %u\nLongitud del Paquete: %u\n", h->caplen, h->len);
    //if ((h->caplen) == (h->len))
    //{
    	ethernet_decoder(bytes, h->caplen);
    //}

}
