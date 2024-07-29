#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

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

void print_hex(const u_char* payload, int len) {
	for (int i = 0; i < len && i < 20; i++) {
		printf("%02x ", payload[i]);
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct ether_header *eth_header = (struct ether_header *) packet;
		printf("Ethernet Header\n");
		printf("Src MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
		printf("Dst MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));

		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
			struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
			char src_ip[INET_ADDRSTRLEN];
			char dst_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
			printf("IP Header\n");
			printf("Src IP: %s\n", src_ip);
			printf("Dst IP: %s\n", dst_ip);

			if (ip_header->ip_p == IPPROTO_TCP) {
				struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
				printf("TCP Header\n");
				printf("Src Port: %d\n", ntohs(tcp_header->source));
				printf("Dst Port: %d\n", ntohs(tcp_header->dest));

				const u_char* payload = packet + sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
				int payload_len = header->caplen - (payload - packet);
				printf("Payload (up to 20 bytes): ");
				print_hex(payload, payload_len);
			}
		}
	}

	pcap_close(pcap);
	return 0;
}

