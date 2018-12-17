#include <netinet/in.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

int arpDecoder(const u_char *bytes, bpf_u_int32 dataLength)
{
	printf("\n************************** ARP *****************************\n\n");

  	struct arphdr *headerARP = (struct arphdr *) bytes;

	printf("Direccion de Hardware: %u\n", headerARP->ar_hrd);
	printf("Format Of Protocol Address: %u\n", headerARP->ar_pro);
	printf("Length Of Hardware Address: %u\n", headerARP->ar_hln);
	printf("Length Of Protocol Address: %u\n", headerARP->ar_pln);
	printf("ARP opcode: %u\n", headerARP->ar_op);

}
