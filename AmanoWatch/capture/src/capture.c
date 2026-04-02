#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "packet.h"
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

// NOTE: memcpy is scattered throughout program, this is costly so I 
// intend on changing it to something more time efficient

// Tells the program that anything starting with 'EXPORT' can be used externally
#define EXPORT __declspec(dllexport)

// Packet capture handle
static pcap_t* global_handle = NULL;
// Initializes global link
static int global_link_type = 0;
// Just so the program knows the size of buffer
static char device_list_buffer[4096];

// header: Initial packet header
// pkt_data: All other existing packet data
// p: Empty packet to fill passed in by python
void ProcessRawData(const struct pcap_pkthdr* header, const u_char* pkt_data, packet* p) {
    memset(p, 0, sizeof(packet)); // Clears packet struct so no garbage can exist
    // Total time is the sum of tv_sec and tv_usec
    p->tv_sec = (long long)header->ts.tv_sec; // Seconds
    p->tv_usec = (long long)header->ts.tv_usec; // Microseconds
    p->payload = NULL;     // Explicitly nullify so error doesnt occur
    p->payload_len = 0;

    int offset = 0; // Tracks where program is in each header offset
    uint16_t eth_type = 0; // Initialize ethernet type

    if (global_link_type == DLT_EN10MB) { // Ethernet
        // Get ethernet header
        struct eth_header* eth = (struct eth_header*)(pkt_data); 
        eth_type = ntohs(eth->type); // Converts ethernet type from big endian to little endian
                                     // (Network Byte Order -> Host Byte Order)
        offset = 14; // Eth header is 14 bytes

        if (eth_type == 0x8100) { // VLAN tag
            // If Vlan tagging is on, the real ethernet header if 2 bytes further in
            eth_type = ntohs(*(uint16_t*)(pkt_data + 16));
            offset = 18; // Shift everything by 4 bytes past VLAN tage
        }

        memcpy(p->src_mac, eth->src_mac, 6);
        memcpy(p->dst_mac, eth->dst_mac, 6);
    }
    else if (global_link_type == DLT_NULL) { // Loopback/Localhost
        uint32_t protocol_family = *(uint32_t*)pkt_data; // Gets protocol type e.g. IPv4 or IPv6
        if (protocol_family == 2) eth_type = 0x0800; // IPv4
        else if (protocol_family == 24) eth_type = 0x86DD; // IPv6
        offset = 4; // Loopback header is 4 bytes
    }
    else return; // Only ethernet and loopback links are supported for now

    int transport_offset = 0; // Tracks where program is in each protocol offset

    if (eth_type == 0x0800) { // IPv4
        // Get IPv4 header
        struct ipv4_header* ip = (struct ipv4_header*)(pkt_data + offset);
        int ip_len = (ip->ver_ihl & 0x0F) * 4; // Gets the length of the IP header in bytes
        p->protocol = ip->proto;
        p->is_ipv6 = 0; // Tells packet that it is not IPv6
        memcpy(p->src_ip, &ip->src_ip, 4);
        memcpy(p->dst_ip, &ip->dst_ip, 4);
        transport_offset = offset + ip_len; // Keeps track of running offset so the program knows where next header is
    }
    else if (eth_type == 0x86DD) { // IPv6
        // Get IPv6 header
        struct ipv6_header* ip6 = (struct ipv6_header*)(pkt_data + offset);
        p->protocol = ip6->next_header; // IPv6 already knows its next header, no need to track it
        p->is_ipv6 = 1; // Tells packet that it is IPv6
        memcpy(p->src_ip, &ip6->src_ip, 16);
        memcpy(p->dst_ip, &ip6->dst_ip, 16);
        transport_offset = offset + 40;

        if (p->protocol == 58) { // ICMPv6
            struct icmp_header* icmp6 = (struct icmp_header*)(pkt_data + transport_offset);

            p->src_port = icmp6->type;
            p->dst_port = icmp6->code;

            p->payload = pkt_data + transport_offset + 8;
            p->payload_len = (header->caplen > (uint32_t)(transport_offset + 8)) ?
                header->caplen - (transport_offset + 8) : 0;

            return;
        }
    }
    else if (eth_type == 0x0806) { // ARP
        // Get ARP header
        struct arp_header* arp = (struct arp_header*)(pkt_data + offset);
        p->protocol = 205; // ARP will be protocol #205 for the sake of simplicity
        p->src_port = ntohs(arp->oper); // src_port of an ARP packet will track for request (1) or reply (2)
        memcpy(p->src_ip, &arp->src_ip, 4);
        memcpy(p->dst_ip, &arp->dst_ip, 4);
        memcpy(p->src_mac, &arp->src_mac, 6); // Reset MAC addresses from ethernet header to the ones stored
        memcpy(p->dst_mac, &arp->dst_mac, 6); // in ARP header because in order to detect spoofing, these ones are needed

        return;
    }

    if (p->protocol == 6) { // TCP
        // Gets TCP header
        struct tcp_header* tcp = (struct tcp_header*)(pkt_data + transport_offset);
        p->src_port = ntohs(tcp->src_port);
        p->dst_port = ntohs(tcp->dst_port);
        p->tcp_flags = tcp->flags;
        int tcp_len = (tcp->offx2 >> 4) * 4; // Gets length of TCP header in bytes
        p->payload = pkt_data + transport_offset + tcp_len; // If applicable, gets payload
        p->payload_len = (header->caplen > (uint32_t)(transport_offset + tcp_len)) ?
            header->caplen - (transport_offset + tcp_len) : 0;
    }
    else if (p->protocol == 17) { // UDP
        // Gets UDP header
        struct udp_header* udp = (struct udp_header*)(pkt_data + transport_offset);
        p->src_port = ntohs(udp->src_port);
        p->dst_port = ntohs(udp->dst_port);
        p->payload = pkt_data + transport_offset + 8;
        p->payload_len = (header->caplen > (uint32_t)(transport_offset + 8)) ?
            header->caplen - (transport_offset + 8) : 0;
    }
}

EXPORT int GetStats(struct pcap_stat* stats) {
    // 1. Safety check: make sure the capture has actually started
    if (global_handle == NULL) {
        return -1;
    }

    // 2. pcap_stats is the built-in function that populates the struct
    // It returns 0 on success, -1 on error
    if (pcap_stats(global_handle, stats) < 0) {
        return -2;
    }

    return 0;
}

// Exported Functions
EXPORT char* GetDevices(char* device_errbuf) {
    pcap_if_t* alldevs;
    pcap_if_t* d;

    // Clear the buffer
    memset(device_list_buffer, 0, sizeof(device_list_buffer));

    if (pcap_findalldevs(&alldevs, device_errbuf) == -1) {
        return "ERROR";
    }

    for (d = alldevs; d; d = d->next) {
        // Concatenate device name and a separator to our buffer
        strcat(device_list_buffer, d->name);

        // Add a description if it exists, using a different separator
        if (d->description) {
            strcat(device_list_buffer, " (");
            strcat(device_list_buffer, d->description);
            strcat(device_list_buffer, ")");
        }

        strcat(device_list_buffer, "|");
    }

    pcap_freealldevs(alldevs);
    return device_list_buffer;
}

EXPORT int InitCapture(const char* device_name, char* errbuf) { // Device name passed in python call
                                                                // I made errbuf also get passed in from python
                                                                // so the python interface can see error messages
    if (global_handle != NULL) {
        pcap_close(global_handle);
        global_handle = NULL;
    }
    // device_name: device to capture traffic on
    // snaplen: size of handle to capture data (in bytes)
    // promiscuous mode: 1 enables promiscuous mode
    // to_ms: milliseconds until packet capture times out
    // errbuff: where error message is stored if handle fails to open
    global_handle = pcap_create(device_name, errbuf);
    pcap_set_snaplen(global_handle, 65535);
    pcap_set_promisc(global_handle, 1);
    pcap_set_timeout(global_handle, 1000);
    pcap_set_buffer_size(global_handle, 32 * 1024 * 1024); // 32MB buffer
    pcap_activate(global_handle);
    // Checks if global_handle opened successfully
    if (global_handle) {
        global_link_type = pcap_datalink(global_handle); // Link-layer header type e.g. loopback, ethernet, etc.
        return 1; // Success
    }
    // Failure, I think i need to print the errbuf or somehow get the error message to python.
    return 0;
}

EXPORT int GetNextPacketCache(packet* packetCache) { // Packet cache passed in by python call
    if (!global_handle) return -1; // Double-checks if global handle exists
    
    int count = 0;
    while (count < 50) {
        struct pcap_pkthdr* header; // Initializes empty packet header
        const u_char* pkt_data; // Initializes empty packet data    
        int result = pcap_next_ex(global_handle, &header, &pkt_data); // Gets next packet, fills header and pkt_data
        // and returns 1 if success, 0 if failure
        if (result == 1) { // Success
            ProcessRawData(header, pkt_data, &packetCache[count]);
            count++;
        } else {
            return result;
        }
    }
    return count;
}

EXPORT void CloseCapture() { // When python program closes, CloseCapture is called
    if (global_handle) {
        pcap_close(global_handle); // Closes capture handle
        global_handle = NULL;
    }
}