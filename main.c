#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ether.h>
#include "decodificadorEthernet.c"
#define LENGTH_CAPTURE 2000


void pcap_handler_callback(u_char * arg, const struct pcap_pkthdr *h, const u_char *bytes);

int i=0;

void printing(){
    printf("Paquete capturado numero:%d\n",i);
    i=i+1;
}

int main(int argc, char **argv)
{
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
    	ethernet_decoder(bytes, h->len);
    //}

}
