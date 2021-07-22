#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "header.h"
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
