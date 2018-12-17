#include <net/ethernet.h>
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "decodificadorIPV4.c"
#include "decodificadorIPV6.c"
#include "decodificadorARP.c"


int ethernet_decoder(const u_char *bytes, bpf_u_int32 dataLength)
{
  struct ether_header *ethernetStruct = (struct ether_header *) bytes;
  printf("\n************************ PROTOCOLO ETHERNET *************************\n\n");
  printf("La Direccion MAC de Destino es:  %s\n", ether_ntoa((struct ether_addr *) ethernetStruct->ether_dhost));
  printf("La Direccion MAC de Origen es %s\n", ether_ntoa((struct ether_addr *) ethernetStruct->ether_shost));
  printf("Este paquete Ethernet contiene el tipo de paquete: 0x%04x\n", ntohs(ethernetStruct->ether_type));
  switch(ntohs(ethernetStruct->ether_type)){
    case ETHERTYPE_IP:
      ip_decoder(bytes + sizeof(*ethernetStruct), dataLength - sizeof(*ethernetStruct));
      break;
    case ETHERTYPE_ARP:
      //printf("Es del tipo ARP\n");
      arpDecoder(bytes + sizeof(*ethernetStruct), dataLength - sizeof(*ethernetStruct));
      break;
    case ETHERTYPE_IPV6:
      //ip6Decoder(bytes + sizeof(*ethernetStruct), dataLength - sizeof(*ethernetStruct));
      break;
  }
}
