#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "packet.h"

// Define EXPORT without the trailing semicolon
#define EXPORT __declspec(dllexport)

static pcap_t* global_handle = NULL;
static int global_link_type = 0;

// Internal parsing logic
void ProcessRawData(const struct pcap_pkthdr* header, const u_char* pkt_data, packet* p) {
    memset(p, 0, sizeof(packet));
    p->tv_sec = (long long)header->ts.tv_sec;
    p->tv_usec = (long long)header->ts.tv_usec;

    int offset = 0;
    uint16_t eth_type = 0;

    if (global_link_type == DLT_EN10MB) {
        struct eth_header* eth = (struct eth_header*)(pkt_data);
        eth_type = ntohs(eth->type);
        offset = 14;
        memcpy(p->src_mac, eth->src_mac, 6);
        memcpy(p->dst_mac, eth->dst_mac, 6);
    }
    else if (global_link_type == DLT_NULL) {
        uint32_t protocol_family = *(uint32_t*)pkt_data;
        if (protocol_family == 2) eth_type = 0x0800;
        else if (protocol_family == 24) eth_type = 0x86DD;
        offset = 4;
    }
    else return;

    int transport_offset = 0;

    if (eth_type == 0x0800) { // IPv4
        struct ipv4_header* ip = (struct ipv4_header*)(pkt_data + offset);
        int ip_len = (ip->ver_ihl & 0x0F) * 4;
        p->protocol = ip->proto;
        p->is_ipv6 = 0;
        memcpy(p->src_ip, &ip->src_ip, 4);
        memcpy(p->dst_ip, &ip->dst_ip, 4);
        transport_offset = offset + ip_len;
    }
    else if (eth_type == 0x86DD) { // IPv6
        struct ipv6_header* ip6 = (struct ipv6_header*)(pkt_data + offset);
        p->protocol = ip6->next_header;
        p->is_ipv6 = 1;
        memcpy(p->src_ip, &ip6->src_ip, 16);
        memcpy(p->dst_ip, &ip6->dst_ip, 16);
        transport_offset = offset + 40;
    }

    if (p->protocol == 6) { // TCP
        struct tcp_header* tcp = (struct tcp_header*)(pkt_data + transport_offset);
        p->src_port = ntohs(tcp->src_port);
        p->dst_port = ntohs(tcp->dst_port);
        p->tcp_flags = tcp->flags;
        int tcp_len = (tcp->offx2 >> 4) * 4;
        p->payload = pkt_data + transport_offset + tcp_len;
        p->payload_len = (header->caplen > (uint32_t)(transport_offset + tcp_len)) ?
            header->caplen - (transport_offset + tcp_len) : 0;
    }
    else if (p->protocol == 17) { // UDP
        struct udp_header* udp = (struct udp_header*)(pkt_data + transport_offset);
        p->src_port = ntohs(udp->src_port);
        p->dst_port = ntohs(udp->dst_port);
        p->payload = pkt_data + transport_offset + 8;
        p->payload_len = (header->caplen > (uint32_t)(transport_offset + 8)) ?
            header->caplen - (transport_offset + 8) : 0;
    }

    // DNS / mDNS Logic
    if (p->src_port == 53 || p->dst_port == 53) p->protocol = 206;
    if (p->src_port == 5353 || p->dst_port == 5353) p->protocol = 207;
}

// Exported Functions
EXPORT int InitCapture(const char* device_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    global_handle = pcap_open_live(device_name, 65536, 1, 1000, errbuf);
    if (global_handle) {
        global_link_type = pcap_datalink(global_handle);
        return 1;
    }
    return 0;
}

EXPORT int GetNextPacket(packet* out_p) {
    if (!global_handle) return -1;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res = pcap_next_ex(global_handle, &header, &pkt_data);
    if (res == 1) {
        ProcessRawData(header, pkt_data, out_p);
        return 1;
    }
    return res;
}

EXPORT void CloseCapture() {
    if (global_handle) {
        pcap_close(global_handle);
        global_handle = NULL;
    }
}