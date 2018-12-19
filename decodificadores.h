#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <netinet/in.h>
#include <net/if_arp.h>

#include <netinet/ip.h>

#include </usr/include/netinet/ip6.h>

#include<netinet/tcp.h>

#include<netinet/udp.h>

#include<netinet/ip_icmp.h>

#include <netinet/icmp6.h>

int ethernet_decoder(const u_char *bytes, bpf_u_int32 dataLength);

int ip_decoder(const u_char *bytes, bpf_u_int32 dataLength);
int arpDecoder(const u_char *bytes, bpf_u_int32 dataLength);
void ip6Decoder(const u_char *bytes, bpf_u_int32 dataLength);

void TCPdecoder(const u_char * Buffer, int Size);
void UDPdecoder(const u_char *Buffer , int Size);
void ICMPdecoder(const u_char * Buffer , int Size);
void ICMPv6decoder(const u_char *bytes, int size);
