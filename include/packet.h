#ifndef PACKET_STRUCTS_H
#define PACKET_STRUCTS_H

#include <stdint.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma pack(push, 1)

typedef struct {
    u_char src_mac[6];
    u_char dst_mac[6];
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint8_t is_ipv6;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t type;
    uint8_t tcp_flags;
    
    long long tv_sec;
    long long tv_usec;
    
    uint32_t payload_len;
    const uint8_t* payload;
} packet;

struct eth_header {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
};

struct ipv4_header {
    u_char  ver_ihl;        // Version (4 bits) + IHL (4 bits)
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    struct in_addr src_ip;
    struct in_addr dst_ip;
};

struct ipv6_header {
    uint32_t v_tc_fl;      // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint16_t payload_len;  // Payload length
    uint8_t  next_header;  // Next Header (replaces the 'proto' field in IPv4)
    uint8_t  hop_limit;    // Hop Limit (replaces 'ttl' in IPv4)
    struct in6_addr src_ip; // Source address (16 bytes / 128 bits)
    struct in6_addr dst_ip;
};

// --- ADDED: Transport Layer Structs ---
struct tcp_header {
    u_short src_port;          // Source port
    u_short dst_port;          // Destination port
    u_int   seq;            // Sequence number
    u_int   ack;            // Ack number
    u_char  offx2;          // Data offset (Header length)
    u_char  flags;
    u_short win;
    u_short sum;
    u_short urp;
};

struct udp_header {
    u_short src_port;          // Source port
    u_short dst_port;          // Destination port
    u_short len;            // Datagram length
    u_short sum;            // Checksum
};

struct icmp_header {
    uint8_t type;     // ICMP Type (e.g., 8 for Request, 0 for Reply)
    uint8_t code;     // ICMP Code (further details)
    uint16_t checksum;
    uint16_t id;       // Identifier
    uint16_t sequence; // Sequence number
};

struct arp_header {
    uint16_t htype;    // Hardware type (1 for Ethernet)
    uint16_t ptype;    // Protocol type (0x0800 for IPv4)
    uint8_t hlen;      // Hardware address length (6)
    uint8_t plen;      // Protocol address length (4)
    uint8_t oper;     // Operation (1 for Request, 2 for Reply)
    uint8_t src_mac[6];    // Sender hardware address
    uint8_t src_ip[4];    // Sender protocol address
    uint8_t dst_mac[6];    // Target hardware address
    uint8_t dst_ip[4];    // Target protocol address
};

#pragma pack(pop)
#endif