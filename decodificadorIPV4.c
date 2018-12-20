#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "decodificadores.h"
//#include "decodificadorTCP.c"
//#include "decodificadorUDP.c"
//#include "decodificadorICMP.c"


int ip_decoder(const u_char *bytes, bpf_u_int32 dataLength)
{

  FILE *Register;
  Register = fopen ( "registroTrafico.csv", "a" );

  printf("\n***************************** IP *****************************\n\n");

  struct ip *ipStruct = (struct ip *) bytes;

  printf("Version: %u\n", ipStruct->ip_v);
  printf("Type Of Service: %u\n", ipStruct->ip_tos);
  printf("Total Length: %u\n", ntohs(ipStruct->ip_len));
  printf("Internet Header Length: %u\n", ipStruct->ip_hl);
  printf("Identification: %u\n", ntohs(ipStruct->ip_id));
  printf("Fragment Offset: %u\n", ipStruct->ip_off & IP_OFFMASK);
  printf("Time To Live: %u\n", ipStruct->ip_ttl);
  printf("Protocol: %u\n", ipStruct->ip_p);
  printf("Header Checksum: %u\n", ipStruct->ip_sum);
  printf("Source Address:   %s\n", inet_ntoa(ipStruct->ip_src));
  printf("Destination Address:  %s\n", inet_ntoa(ipStruct->ip_dst));

  fprintf(Register, "%s;",inet_ntoa(ipStruct->ip_src));
  fclose(Register);
  switch(ipStruct->ip_p)
  {
    case IPPROTO_ICMP:
      printf("Contiene el Protocolo ICMP\n");
      ICMPdecoder(bytes + sizeof(*ipStruct), dataLength - sizeof(*ipStruct));
      break;
    case IPPROTO_TCP:
      printf("Contiene el Protocolo TCP\n");
      TCPdecoder(bytes + sizeof(*ipStruct), dataLength - sizeof(*ipStruct));
      break;
    case IPPROTO_UDP:
      printf("Contiene el Protocolo UDP\n");
      UDPdecoder(bytes + sizeof(*ipStruct), dataLength - sizeof(*ipStruct));
      break;
  }
}
