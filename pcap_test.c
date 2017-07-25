#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <./net/ethernet.h>
#include <./arpa/inet.h>

#define	ETH_ALEN 6

typedef	u_int32_t tcp_seq;

struct _ether_header{
  	unsigned char ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  	unsigned char ether_shost[ETH_ALEN];	/* source ether addr	*/
 	short ether_type;		        /* packet type ID field	*/
};

struct _ip_header{
    unsigned short int ihl:4;
    unsigned short int ver:4;
    unsigned char tos;
    unsigned short int length;
    unsigned short int identification;
    unsigned short int flag_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short int checksum;
    struct in_addr ucSource;
    struct in_addr ucDestination;
};

struct _tcp_header{
	unsigned short th_sport;	/* source port */
	unsigned short th_dport;	/* destination port */
	unsigned int th_seq;		/* sequence number */
	unsigned int th_ack;		/* acknowledgement  */
	unsigned char th_offset;	/* data offset */
	unsigned char th_flags;
	unsigned short int th_win;		/* window */
	unsigned short int th_sum;		/* checksum */
	unsigned short int th_urp;		/* urgent pointer */
};

void print_mac(u_char *mac){
	int i;
	for(i=0;i<6;i++){
		printf("%02x",(int)(*(unsigned char*)(&mac[i])));
		if(i == 5)
			continue;
		printf(":");
	}
	printf("\n");
}


int main(int argc, char *argv[]){
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	int i,size_ip;
	int data_size;	
 	unsigned char size_th;
	struct _ether_header *eh;
	char buf[INET_ADDRSTRLEN];
	struct _ip_header *ih;
	struct _tcp_header *th;
	const u_char *packet_data;
	const char *data;
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	while(1){
		packet = pcap_next_ex(handle, 3, &packet_data);
		if(packet_data == 0)
			continue;
		else if(packet == 1){	// success
			eh = (struct _ether_header*)(packet_data);
			ih = (struct _ip_header*)(packet_data+14);

			size_ip = (ih->ihl)*4;
			th = (struct _tcp_header*)(packet_data + 14 + size_ip);
			size_th = (th->th_offset >> 2);
			data = (char *)(packet_data + 14 + size_ip + size_th);
			data_size = ntohs(ih->length)*4-size_ip - size_th;
			if(ntohs(eh->ether_type) == ETHERTYPE_IP && (ih->protocol) == IPPROTO_TCP){
				printf("=====================================\n");
				printf("MAC address[shost] : ");
				print_mac(eh->ether_shost);
				printf("MAC address[dhost] : ");
				print_mac(eh->ether_dhost);
				inet_ntop(AF_INET,&(ih->ucSource).s_addr, buf, sizeof(buf));
				printf("source ip : %s \n", buf);
				inet_ntop(AF_INET,&(ih->ucDestination).s_addr, buf, sizeof(buf));
				printf("dest ip : %s \n", buf);
				printf("sour port : %d \n", ntohs(th->th_sport));
				printf("dest port : %d \n", ntohs(th->th_dport));
				printf("data size : %d \n", data_size);
				printf("\n===============data==================\n");
				for(i=0;i<data_size;i++){
					printf("%c",data[i]);
				}
				printf("\n=====================================\n");
			}
		}
		else if(packet < 0){
			exit(1);
		}
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
