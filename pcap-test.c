#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>


#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800 //ip
#define IPP_TCP 0x06

//just for print
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


typedef struct {
	char* dev_;
} Param;

//Ethernet Header 14byte
struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */ //6byte
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */		//6byte
    u_int16_t ether_type;                 /* protocol */		//2byte
};

// IPv4 Header 20byte
struct ipv4_header {
    uint8_t  ip_vhl;	// Header length + version 	1byte
    uint8_t  ip_tos;	// type of service			1byte
    uint16_t ip_len;	// total length				2byte
    uint16_t ip_id;		// identification			2byte
    uint16_t ip_off;	// fragment offset			2byte
    uint8_t  ip_ttl;	// TTL(time to live)		1byte
    uint8_t  ip_p;		// protocol					1byte
    uint16_t ip_sum;	// checksum					2byte
    uint32_t ip_src;	// source address			4byte
    uint32_t ip_dst;	// dest address				4byte
};


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct tcp_hdr
{
    u_int16_t th_sport;       /* source port */					//2byte
    u_int16_t th_dport;       /* destination port */			//2byte
    u_int32_t th_seq;         /* sequence number */				//4byte
    u_int32_t th_ack;         /* acknowledgement number */		//4byte
    u_int8_t th_x2off;         /* (unused) + data offset*/		//1byte
    u_int8_t th_flags;       /* control flags */				//1byte
	u_int8_t th_opt;          /*th option*/						//1byte
    u_int16_t th_win;         /* window */						//2byte
    u_int16_t th_sum;         /* checksum */					//2byte
    u_int16_t th_urp;         /* urgent pointer */				//1byte
};


Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    char errbuf[PCAP_ERRBUF_SIZE];  //buffer
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
        const u_char* packet;       //declare var packet(get packet data)
		int res = pcap_next_ex(pcap, &header, &packet);

        //consider exception
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        // map struct
        struct ethernet_hdr* eth_hdr = (struct ethernet_hdr*)packet;
        struct ipv4_header* ip_hdr = (struct ipv4_header*)(packet + sizeof(struct ethernet_hdr));
        struct tcp_hdr* tcp_hdr = (struct tcp_hdr*)(packet + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_header));


        // Print the required fields
        printf("source ethernet address ");
        for (int i = 0; i < 6; i++) {
            printf("%02x", eth_hdr->ether_shost[i]);
        }
        printf("\n");

        printf("destination ethernet address: ");
        for (int i = 0; i < 6; i++) {
            printf("%02x", eth_hdr->ether_dhost[i]);
        }
        printf("\n");

//        not ip typeEthernet Type: 0x0008
        if (ntohs(eth_hdr->ether_type) !=ETHERTYPE_IP){
            continue;
        }

        printf("source ip address: %0x\n", ip_hdr->ip_src);
        printf("destination ip address: %0x\n", ip_hdr->ip_src);

        if (ip_hdr->ip_p !=IPP_TCP){
            continue;
        }


        printf("source port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("destination port: %d\n", ntohs(tcp_hdr->th_dport));
//		printf("%d bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
