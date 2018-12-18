#include <netinet/in.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

int arpDecoder(const u_char *bytes, bpf_u_int32 dataLength)
{
	printf("\n************************** ARP *****************************\n\n");

  	struct arphdr *headerARP = (struct arphdr *) bytes;

	printf("Format of hardware Address: %u\n", headerARP->ar_hrd);
	printf("Format Of Protocol Address: %u\n", headerARP->ar_pro);
	printf("Length Of Hardware Address: %u\n", headerARP->ar_hln);
	printf("Length Of Protocol Address: %u\n", headerARP->ar_pln);
	//printf("Sender hardware address: %s\n", headerARP->__ar_sha);
	printf("ARP opcode: %u\n", headerARP->ar_op);

		printf("\nSender MAC: ");
		for(int i=0; i<6;i++)
        printf("%02X:", headerARP->__ar_sha[i]);

    printf("\nSender IP: ");

    for(int i=0; i<4;i++)
        printf("%d.", headerARP->__ar_sip[i]);

    printf("\nTarget MAC: ");

    for(int i=0; i<6;i++)
        printf("%02X:", headerARP->__ar_tha[i]);

    printf("\nTarget IP: ");

    for(int i=0; i<4; i++)
        printf("%d.", headerARP->__ar_tip[i]);

    printf("\n");

}
