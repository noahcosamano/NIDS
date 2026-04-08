#include "packet.h"

int IsTLS(packet* p) { // Returns 1 if TLS handshake detected, 0 otherwise
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 5) {
        return 0;
    }

    // Points to start of TCP payload
    const uint8_t* data = p->payload;

    /* TLS Record Layer Check:
       Byte 0: Content Type (0x16 = Handshake)
       Byte 1: Major Version (0x03)
       Byte 2: Minor Version (0x01, 0x02, 0x03 for TLS 1.0, 1.1, 1.2/1.3)
    */
    if (data[0] == 0x16 && data[1] == 0x03) {
        if (data[2] >= 0x01 && data[2] <= 0x03) {
            if (p->payload_len >= 6 && data[5] == 0x01) {
                p->app_protocol = 208;
                return 1;
            }
            p->app_protocol = 208;
            return 1;
        }
    }

    return 0;
}

int IsQUIC(packet* p) { // Returns 1 if packet is QUIC, 0 otherwise
    if (!p || p->protocol != 17 || p->payload == NULL || p->payload_len < 5) {
        return 0;
    }

    const uint8_t* data = p->payload;

    if ((data[0] & 0xC0) == 0xC0) {
        // Check for Version 1 (0x00000001) at offset 1
        uint32_t version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

        if (version == 0x00000001) {
            p->app_protocol = 209;
            return 1; // It's QUIC v1 Initial
        }

        // Google's older versions (GQUIC) often use ASCII like 'Q046'
        if (data[1] == 'Q') {
            p->app_protocol = 209;
            return 1;
        }
    }

    return 0;
}

int IsDNS(packet* p) { // Returns 1 if packet is DNS, 0 otherwise
    if (!p || p->payload == NULL || p->payload_len < 12) return 0;

    // Port validation first
    int is_dns_port = (p->src_port == 53 || p->dst_port == 53 ||
                       p->src_port == 5353 || p->dst_port == 5353);

    if (!is_dns_port) return 0;

    // Heuristic validation next
    // DNS headers have specific flags at offset 2 and 3
    const uint8_t* dns = p->payload;

    // Check if question count is > 0
    uint16_t q_count = (dns[4] << 8) | dns[5]; // DNS is big endian, questions at payload[4] and [5]

    if (q_count == 0 || q_count > 20) return 0; // Likely SSDP or random UDP

    if (p->src_port == 5353 || p->dst_port == 5353) p->app_protocol = 207; // MDNS
    else p->app_protocol = 206; // Regular DNS

    return 1;
}

int IsTELNET(packet* p) {
    if (p->protocol == 6 && (p->src_port == 23 || p->dst_port == 23)) {
        if (p->payload_len > 0 && p->payload[0] == 0xFF) {
            // This is a Telnet Control message
            p->app_protocol = 210;
            return 1;
        }
    }

    return 0;
}

int IsFTP(packet* p) {
    // FTP is strictly TCP
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 3) {
        return 0;
    }

    // Check standard FTP Control Port
    if (p->src_port == 21 || p->dst_port == 21) {
        const uint8_t* data = p->payload;

        // Verify it looks like ASCII text (Optional but safer)
        // Most FTP commands or responses start with a letter or a digit
        if ((data[0] >= 'A' && data[0] <= 'Z') || (data[0] >= '0' && data[0] <= '9')) {
            p->app_protocol = 211; // Assign an ID for FTP
            return 1;
        }
    }
    return 0;
}

int IsTFTP(packet* p) {
    // TFTP is strictly UDP
    if (!p || p->protocol != 17 || p->payload == NULL || p->payload_len < 4) {
        return 0;
    }

    // Check standard TFTP Port
    if (p->dst_port == 69 || p->src_port == 69) {
        const uint8_t* data = p->payload;

        /* TFTP Header: First 2 bytes are the Opcode (Big Endian)
           Common Opcodes: 1 (Read), 2 (Write), 3 (Data), 4 (Ack), 5 (Error)
        */
        if (data[0] == 0x00 && (data[1] >= 0x01 && data[1] <= 0x05)) {
            p->app_protocol = 212;
            return 1;
        }
    }
    return 0;
}

int IsNFS(packet* p) {
    if (!p || p->payload == NULL || p->payload_len < 24) {
        return 0;
    }

    const uint8_t* data = p->payload;
    uint32_t rpc_payload_offset = 0;

    // TCP Catch: RPC over TCP adds a 4-byte "Record Marking" length header
    if (p->protocol == 6) {
        rpc_payload_offset = 4;
        if (p->payload_len < 28) return 0;
    }

    // Look for the RPC Program Number for NFS: 100003 (0x000186A3)
    // In a "Call" (Type 0), this is at offset 12 (relative to RPC start)
    const uint8_t* rpc_header = data + rpc_payload_offset;

    // Check RPC Version == 2 (Bytes 8-11) AND Program == NFS (Bytes 12-15)
    if (rpc_header[11] == 0x02 &&
        rpc_header[12] == 0x00 && rpc_header[13] == 0x01 &&
        rpc_header[14] == 0x86 && rpc_header[15] == 0xA3) {

        p->app_protocol = 213; // Assign an ID for NFS
        return 1;
    }

    return 0;
}

int IsSMTP(packet* p) {
    // SMTP is strictly TCP
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 4) {
        return 0;
    }

    // Check standard SMTP ports
    if (p->dst_port == 25 || p->src_port == 25 ||
        p->dst_port == 587 || p->src_port == 587) {

        const uint8_t* data = p->payload;

        // Check for Server Greeting "220 "
        if (data[0] == '2' && data[1] == '2' && data[2] == '0') {
            p->app_protocol = 214; // SMTP ID
            return 1;
        }

        // Check for Client Handshake "EHLO" or "HELO"
        if (data[0] == 'E' && data[1] == 'H' && data[2] == 'L' && data[3] == 'O') {
            p->app_protocol = 214;
            return 1;
        }
        if (data[0] == 'H' && data[1] == 'E' && data[2] == 'L' && data[3] == 'O') {
            p->app_protocol = 214;
            return 1;
        }
    }
    return 0;
}

int IsLPD(packet* p) {
    // LPD is strictly TCP
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 2) {
        return 0;
    }

    // Check standard LPD Port
    if (p->dst_port == 515 || p->src_port == 515) {
        const uint8_t* data = p->payload;

        /* LPD Commands: First byte is the command,
           followed by the printer 'Queue Name' and a Newline (0x0A).
        */
        if (data[0] >= 0x01 && data[0] <= 0x05) {
            // Further verification: Check if the command is followed by ASCII
            // (Queue names are usually text like 'lp' or 'raw')
            if (p->payload_len > 1 && (data[1] >= 32 && data[1] <= 126)) {
                p->app_protocol = 215; // Assign a custom ID for LPD
                return 1;
            }
        }
    }
    return 0;
}

int IsSNMP(packet* p) {
    // SNMP is UDP
    if (!p || p->protocol != 17 || p->payload == NULL || p->payload_len < 8) {
        return 0;
    }

    // Check standard SNMP Ports
    if (p->dst_port == 161 || p->src_port == 161 ||
        p->dst_port == 162 || p->src_port == 162) {

        const uint8_t* data = p->payload;

        /* Check for ASN.1 Sequence header:
           data[0] == 0x30 (Sequence)
           data[2] == 0x02 (Integer Tag)
           data[3] == 0x01 (Length of Version)
        */
        if (data[0] == 0x30 && data[2] == 0x02 && data[3] == 0x01) {
            // Check if version is v1(0), v2c(1), or v3(3)
            if (data[4] == 0x00 || data[4] == 0x01 || data[4] == 0x03) {
                p->app_protocol = 216; // Custom ID for SNMP
                return 1;
            }
        }
    }
    return 0;
}

int IsDHCP(packet* p) {
    // DHCP is strictly UDP
    if (!p || p->protocol != 17 || p->payload == NULL || p->payload_len < 240) {
        return 0;
    }

    // Check standard DHCP Ports
    if ((p->src_port == 67 && p->dst_port == 68) ||
        (p->src_port == 68 && p->dst_port == 67)) {

        const uint8_t* data = p->payload;

        /* Verify the Magic Cookie at Offset 236
           Hex: 63 82 53 63
        */
        if (data[236] == 0x63 && data[237] == 0x82 &&
            data[238] == 0x53 && data[239] == 0x63) {

            p->app_protocol = 217; // Assign an ID for DHCP
            return 1;
        }
    }
    return 0;
}

int IsHTTP(packet* p) {
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 4) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // Check for common HTTP verbs
    if (memcmp(data, "GET ", 4) == 0 ||
        memcmp(data, "POST", 4) == 0 ||
        memcmp(data, "PUT ", 4) == 0 ||
        memcmp(data, "HEAD", 4) == 0) {

        p->app_protocol = 218; // ID for HTTP
        return 1;
    }

    // Check for Server Response: "HTTP/"
    if (p->payload_len >= 5 && memcmp(data, "HTTP/", 5) == 0) {
        p->app_protocol = 218;
        return 1;
    }

    return 0;
}

int IsHTTPS(packet* p) {
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 5) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // 0x16 = Handshake, 0x03 = Major Version SSL/TLS
    if (data[0] == 0x16 && data[1] == 0x03) {
        if (data[2] >= 0x01 && data[2] <= 0x03) {
            p->app_protocol = 219; // ID for HTTPS/TLS
            return 1;
        }
    }
    return 0;
}

int IsPOP3(packet* p) {
    // POP is strictly TCP
    if (!p || p->protocol != 6 || p->payload == NULL || p->payload_len < 4) {
        return 0;
    }

    // Check standard POP3 Port
    if (p->dst_port == 110 || p->src_port == 110) {
        const uint8_t* data = p->payload;

        // Server Greeting: "+OK "
        if (data[0] == '+' && data[1] == 'O' && data[2] == 'K') {
            p->app_protocol = 220; // Assign ID for POP3
            return 1;
        }

        // Client Commands: USER, PASS, STAT, LIST, RETR, QUIT
        if (memcmp(data, "USER", 4) == 0 || memcmp(data, "STAT", 4) == 0 ||
            memcmp(data, "LIST", 4) == 0 || memcmp(data, "QUIT", 4) == 0) {
            p->app_protocol = 220;
            return 1;
        }
    }
    return 0;
}