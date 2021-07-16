#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};
struct libnet_ipv4_hdr
{
    u_int8_t version;
    u_int8_t ip_tos;       //1
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};
struct payload{
    u_int8_t  data[64];
};
bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}
void ethernet(const u_char* packet){
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)packet;
    printf("Ethernet Header's src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    printf("Ethernet Header's dest mac : %02x:%02x:%02x:%02x:%02x:%02x\n\n",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
}
void ip(const u_char* packet){
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)packet;
    ip->ip_src.s_addr = ntohl(ip->ip_src.s_addr);
    ip->ip_dst.s_addr = ntohl(ip->ip_dst.s_addr);
    printf("IP Header's src ip : %d.%d.%d.%d\n",(ip->ip_src.s_addr&0xff000000)>>24,(ip->ip_src.s_addr&0x00ff0000)>>16,(ip->ip_src.s_addr&0x0000ff00)>>8,ip->ip_src.s_addr&0x000000ff);
    printf("IP Header's dest ip : %d.%d.%d.%d\n\n",(ip->ip_dst.s_addr&0xff000000)>>24,(ip->ip_dst.s_addr&0x00ff0000)>>16,(ip->ip_dst.s_addr&0x0000ff00)>>8,ip->ip_dst.s_addr&0x000000ff);
}
void tcp(const u_char* packet){
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)packet;
    tcp->th_sport = ntohs(tcp->th_sport);
    tcp->th_dport = ntohs(tcp->th_dport);
    printf("TCP Header's src port : %d\n",tcp->th_sport);
    printf("TCP Header's dest port : %d\n\n",tcp->th_dport);
}
void payload(const u_char* packet){
    struct payload* payload = (struct payload*)packet;
    printf("Payload : ");
    for(int i = 0; i<64; i++){
        printf("%02x ",payload->data[i]);
    }
    printf("\n\n");
}
int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    printf("%d",sizeof(uint32_t));
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
        printf("%u bytes captured\n", header->caplen);

        ethernet(packet);
        ip(packet+14);
        tcp(packet+34);
        payload(packet+54);
    }
    pcap_close(pcap);
}
