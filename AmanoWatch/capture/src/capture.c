#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "packet.h"
#include "inspect.h"
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
    p->payload_len = 0;
    p->app_protocol = 0;

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

            p->payload_len = (header->caplen > (uint32_t)(transport_offset + 8)) ?
                header->caplen - (transport_offset + 8) : 0;
            if (p->payload_len > sizeof(p->payload))
                p->payload_len = sizeof(p->payload);
            memcpy(p->payload, pkt_data + transport_offset + 8, p->payload_len);

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

        p->payload_len = (header->caplen > (uint32_t)(transport_offset + tcp_len)) ?
            header->caplen - (transport_offset + tcp_len) : 0;
        if (p->payload_len > sizeof(p->payload))
            p->payload_len = sizeof(p->payload);
        memcpy(p->payload, pkt_data + transport_offset + tcp_len, p->payload_len);

        // The functions below take a TCP packet and inspect payload to check for application protocol
        if (IsTLS(p)) {}
        else if (IsDNS(p)) {}
        else if (IsTELNET(p)) {}
        else if (IsFTP(p)) {}
        else if (IsNFS(p)) {}
        else if (IsSMTP(p)) {}
        else if (IsLPD(p)) {}
        else if (IsHTTP(p)) {}
        else if (IsHTTPS(p)) {}
        else if (IsPOP3(p)) {}
    }
    else if (p->protocol == 17) { // UDP
        // Gets UDP header
        struct udp_header* udp = (struct udp_header*)(pkt_data + transport_offset);
        p->src_port = ntohs(udp->src_port);
        p->dst_port = ntohs(udp->dst_port);
        p->payload_len = (header->caplen > (uint32_t)(transport_offset + 8)) ?
            header->caplen - (transport_offset + 8) : 0;
        if (p->payload_len > sizeof(p->payload))
            p->payload_len = sizeof(p->payload);
        memcpy(p->payload, pkt_data + transport_offset + 8, p->payload_len);

        // The functions below take a UDP packet and inspect payload to check for application protocol
        if (IsQUIC(p)) {}
        else if (IsDNS(p)) {}
        else if (IsTFTP(p)) {}
        else if (IsNFS(p)) {}
        else if (IsSNMP(p)) {}
        else if (IsDHCP(p)) {}
        else if (IsLLMNR(p)) {}
        else if (IsSSDP(p)) {}
    }

    else if (p->protocol == 2) {  // IGMP sits directly on IP
        IsIGMPV2(p);
    }

    else if (p->protocol == 1) { // ICMP (IPv4)
        struct icmp_header* icmp = (struct icmp_header*)(pkt_data + transport_offset);

        p->src_port = icmp->type;
        p->dst_port = icmp->code;

        p->payload_len = (header->caplen > (uint32_t)(transport_offset + 8)) ?
            header->caplen - (transport_offset + 8) : 0;
        if (p->payload_len > sizeof(p->payload))
            p->payload_len = sizeof(p->payload);
        memcpy(p->payload, pkt_data + transport_offset + 8, p->payload_len);
    }
}

EXPORT int GetStats(struct pcap_stat* stats) { // Gets stats of packet capture e.g. packets captured, packet loss, etc.
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
EXPORT char* GetDevices(char* device_errbuf) { // 'device_errbuf' stores error message if system fails to get devices
    pcap_if_t* alldevs; // Stores all devices on the system
    pcap_if_t* d;

    // Clear the buffer
    memset(device_list_buffer, 0, sizeof(device_list_buffer)); // Resets device buffer memory

    if (pcap_findalldevs(&alldevs, device_errbuf) == -1) { // Returns -1 if failed
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
    return device_list_buffer; // Returns character array that contains the name of all devices
}

EXPORT int InitCapture(const char* device_name, char* errbuf) { // Device name passed in python call
    // I made errbuf also get passed in from python
    // so the python interface can see error messages
    if (global_handle != NULL) {
        pcap_close(global_handle);
        global_handle = NULL;
    }

    global_handle = pcap_create(device_name, errbuf);
    pcap_set_snaplen(global_handle, 65535); // The max length of each capture
    pcap_set_promisc(global_handle, 1); // 1 enables promiscuous mode, 0 disables it
    pcap_set_timeout(global_handle, 100); // 100 ms timeout on packet
    pcap_set_buffer_size(global_handle, 256 * 1024 * 1024); // 256MB buffer
    pcap_activate(global_handle);
    // Checks if global_handle opened successfully
    if (global_handle) {
        global_link_type = pcap_datalink(global_handle); // Link-layer header type e.g. loopback, ethernet, etc.
        return 1; // Success
    }
    // Failure, I think i need to print the errbuf or somehow get the error message to python.
    return 0;
}

EXPORT int GetNextPacketCache(packet* packetCache, int max_count) { // Packet cache passed in by python call
    if (!global_handle) return -1; // Double-checks if global handle exists
    if (max_count <= 0) return 0;

    int count = 0;
    while (count < max_count) {
        struct pcap_pkthdr* header; // Initializes empty packet header
        const u_char* pkt_data; // Initializes empty packet data    
        int result = pcap_next_ex(global_handle, &header, &pkt_data); // Gets next packet, fills header and pkt_data
        // and returns 1 if success, 0 if failure
        if (result == 1) { // Success
            ProcessRawData(header, pkt_data, &packetCache[count]);
            count++;
        } else if (result == 0) {
            return count;
        } else {
            return (count > 0) ? count : result;
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