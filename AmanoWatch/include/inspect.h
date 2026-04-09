#include "packet.h"

// IsTLS and IsHTTPS use identical byte patterns. Port 443 is the split:
// IsHTTPS owns 443, IsTLS owns everything else (e.g. 8443, STARTTLS, etc.)

int IsTLS(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 5) {
        return 0;
    }

    if (p->src_port == 443 || p->dst_port == 443) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // TLS record header: [0]=0x16 (Handshake), [1]=0x03 (major), [2]=minor
    // minor 0x01=TLS1.0, 0x02=TLS1.1, 0x03=TLS1.2 and TLS1.3
    if (data[0] == 0x16 && data[1] == 0x03 && data[2] >= 0x01 && data[2] <= 0x03) {
        p->app_protocol = 208;
        return 1;
    }

    return 0;
}

int IsQUIC(packet* p) {
    if (!p || p->protocol != 17 || p->payload_len < 5) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // Long header packets have the two high bits set (0xC0)
    if ((data[0] & 0xC0) == 0xC0) {
        uint32_t version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

        if (version == 0x00000001) {  // QUIC v1 (RFC 9000)
            p->app_protocol = 209;
            return 1;
        }

        // GQUIC versions start with 'Q' followed by a 3-digit ASCII version, e.g. "Q046"
        if (data[1] == 'Q') {
            p->app_protocol = 209;
            return 1;
        }
    }

    return 0;
}

int IsDNS(packet* p) {
    if (!p || p->payload_len < 12) return 0;

    int is_dns_port = (p->src_port == 53 || p->dst_port == 53 ||
        p->src_port == 5353 || p->dst_port == 5353);
    if (!is_dns_port) return 0;

    const uint8_t* dns = p->payload;

    // Flags word is at bytes 2-3. Bits 14-11 are the Opcode field.
    // Opcode must be 0 (standard query). Mask 0x78 isolates bits 6-3 of the high byte.
    // Anything non-zero here is an unusual op (IQUERY, STATUS, etc.) or not DNS at all.
    uint8_t flags_hi = dns[2];
    if ((flags_hi & 0x78) != 0) return 0;

    // Question count at bytes 4-5, big endian
    uint16_t q_count = (dns[4] << 8) | dns[5];
    if (q_count == 0 || q_count > 20) return 0;  // 0 is a response with no question, >20 is garbage

    if (p->src_port == 5353 || p->dst_port == 5353) p->app_protocol = 207;  // mDNS
    else p->app_protocol = 206;

    return 1;
}

int IsTELNET(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 1) {
        return 0;
    }

    if (p->src_port == 23 || p->dst_port == 23) {
        // 0xFF = IAC (Interpret As Command), the start of any Telnet control sequence
        if (p->payload[0] == 0xFF) {
            p->app_protocol = 210;
            return 1;
        }
    }

    return 0;
}

int IsFTP(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 3) {
        return 0;
    }

    if (p->src_port == 21 || p->dst_port == 21) {
        const uint8_t* data = p->payload;

        // Commands are uppercase ASCII (e.g. "USER", "RETR"), responses are 3-digit codes
        if ((data[0] >= 'A' && data[0] <= 'Z') || (data[0] >= '0' && data[0] <= '9')) {
            p->app_protocol = 211;
            return 1;
        }
    }
    return 0;
}

int IsTFTP(packet* p) {
    if (!p || p->protocol != 17 || p->payload_len < 4) {
        return 0;
    }

    if (p->dst_port == 69 || p->src_port == 69) {
        const uint8_t* data = p->payload;

        // Opcode is big endian at bytes 0-1
        // 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR
        if (data[0] == 0x00 && data[1] >= 0x01 && data[1] <= 0x05) {
            p->app_protocol = 212;
            return 1;
        }
    }
    return 0;
}

int IsNFS(packet* p) {
    if (!p || p->payload_len < 24) {
        return 0;
    }

    const uint8_t* data = p->payload;
    uint32_t rpc_payload_offset = 0;

    // RPC over TCP prepends a 4-byte Record Marking header (RFC 5531)
    if (p->protocol == 6) {
        rpc_payload_offset = 4;
        if (p->payload_len < 28) return 0;
    }

    const uint8_t* rpc = data + rpc_payload_offset;

    // Bytes 4-7 are the Message Type: 0=Call, 1=Reply
    // Without this check, NFS replies from the server also matched
    if (rpc[4] != 0x00 || rpc[5] != 0x00 || rpc[6] != 0x00 || rpc[7] != 0x00) {
        return 0;
    }

    // Bytes 8-11: RPC version (must be 2)
    // Bytes 12-15: Program number for NFS = 100003 (0x000186A3)
    if (rpc[8] == 0x00 && rpc[9] == 0x00 &&
        rpc[10] == 0x00 && rpc[11] == 0x02 &&
        rpc[12] == 0x00 && rpc[13] == 0x01 &&
        rpc[14] == 0x86 && rpc[15] == 0xA3) {
        p->app_protocol = 213;
        return 1;
    }

    return 0;
}

int IsSMTP(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 4) {
        return 0;
    }

    // 25 = standard relay, 587 = submission (authenticated clients)
    if (p->dst_port == 25 || p->src_port == 25 ||
        p->dst_port == 587 || p->src_port == 587) {

        const uint8_t* data = p->payload;

        if (data[0] == '2' && data[1] == '2' && data[2] == '0') {  // server greeting
            p->app_protocol = 214;
            return 1;
        }
        if (memcmp(data, "EHLO", 4) == 0 || memcmp(data, "HELO", 4) == 0) {  // client hello
            p->app_protocol = 214;
            return 1;
        }
    }
    return 0;
}

int IsLPD(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 2) {
        return 0;
    }

    if (p->dst_port == 515 || p->src_port == 515) {
        const uint8_t* data = p->payload;

        // LPD command byte: 0x01=print, 0x02=receive job, 0x03=report short, 0x04=report long, 0x05=remove
        // Followed by the queue name, which is printable ASCII
        if (data[0] >= 0x01 && data[0] <= 0x05 &&
            p->payload_len > 1 && data[1] >= 32 && data[1] <= 126) {
            p->app_protocol = 215;
            return 1;
        }
    }
    return 0;
}

int IsSNMP(packet* p) {
    if (!p || p->protocol != 17 || p->payload_len < 8) {
        return 0;
    }

    // 161 = agent, 162 = trap receiver
    if (p->dst_port == 161 || p->src_port == 161 ||
        p->dst_port == 162 || p->src_port == 162) {

        const uint8_t* data = p->payload;

        // SNMP is wrapped in an ASN.1 SEQUENCE. Layout for short-form encoding:
        //   [0] 0x30       SEQUENCE tag
        //   [1] < 0x80     length byte (short form, value < 128)
        //   [2] 0x02       INTEGER tag (version field)
        //   [3] 0x01       length of version integer (1 byte)
        //   [4] 0x00/01/03 version: 0=SNMPv1, 1=SNMPv2c, 3=SNMPv3
        //
        // If [1] >= 0x80 it's long-form encoding, where [2] is another length byte
        // not the INTEGER tag — skipping those packets avoids a false positive
        if (data[0] == 0x30 && data[1] < 0x80 &&
            data[2] == 0x02 && data[3] == 0x01 &&
            (data[4] == 0x00 || data[4] == 0x01 || data[4] == 0x03)) {
            p->app_protocol = 216;
            return 1;
        }
    }
    return 0;
}

int IsDHCP(packet* p) {
    if (!p || p->protocol != 17 || p->payload_len < 240) {
        return 0;
    }

    // Server is always 67, client is always 68
    if ((p->src_port == 67 && p->dst_port == 68) ||
        (p->src_port == 68 && p->dst_port == 67)) {

        const uint8_t* data = p->payload;

        // Magic cookie at offset 236 marks the start of the options field: 99.130.83.99
        if (data[236] == 0x63 && data[237] == 0x82 &&
            data[238] == 0x53 && data[239] == 0x63) {
            p->app_protocol = 217;
            return 1;
        }
    }
    return 0;
}

int IsHTTP(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 4) {
        return 0;
    }

    if (p->src_port == 443 || p->dst_port == 443) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // All method checks use 4 bytes. Single-space methods (GET, PUT) include the space.
    if (memcmp(data, "GET ", 4) == 0 ||
        memcmp(data, "POST", 4) == 0 ||
        memcmp(data, "PUT ", 4) == 0 ||
        memcmp(data, "HEAD", 4) == 0 ||
        memcmp(data, "DELE", 4) == 0 ||  // DELETE
        memcmp(data, "PATC", 4) == 0 ||  // PATCH
        memcmp(data, "OPTI", 4) == 0) {  // OPTIONS
        p->app_protocol = 218;
        return 1;
    }

    if (p->payload_len >= 5 && memcmp(data, "HTTP/", 5) == 0) {  // server response
        p->app_protocol = 218;
        return 1;
    }

    return 0;
}

int IsHTTPS(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 5) {
        return 0;
    }

    if (p->src_port != 443 && p->dst_port != 443) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // Same TLS record header as IsTLS — port is the only thing separating the two
    if (data[0] == 0x16 && data[1] == 0x03 && data[2] >= 0x01 && data[2] <= 0x03) {
        p->app_protocol = 219;
        return 1;
    }
    return 0;
}

int IsPOP3(packet* p) {
    if (!p || p->protocol != 6 || p->payload_len < 4) {
        return 0;
    }

    if (p->dst_port == 110 || p->src_port == 110) {
        const uint8_t* data = p->payload;

        if (data[0] == '+' && data[1] == 'O' && data[2] == 'K') {  // server response
            p->app_protocol = 220;
            return 1;
        }

        if (memcmp(data, "USER", 4) == 0 || memcmp(data, "STAT", 4) == 0 ||
            memcmp(data, "LIST", 4) == 0 || memcmp(data, "QUIT", 4) == 0) {
            p->app_protocol = 220;
            return 1;
        }
    }
    return 0;
}

int IsLLMNR(packet* p) {
    // LLMNR runs on UDP port 5355 (and TCP, but almost never in practice)
    if (!p || p->protocol != 17 || p->payload_len < 12) {
        return 0;
    }

    if (p->src_port != 5355 && p->dst_port != 5355) return 0;

    const uint8_t* data = p->payload;

    // Header layout mirrors DNS exactly. Opcode bits 14-11 of the flags
    // word (byte 2) must be 0, same check as IsDNS
    uint8_t flags_hi = data[2];
    if ((flags_hi & 0x78) != 0) return 0;

    uint16_t q_count = (data[4] << 8) | data[5];
    if (q_count == 0 || q_count > 20) return 0;

    p->app_protocol = 221;
    return 1;
}

int IsIGMPV2(packet* p) {
    // IGMP sits directly on IP (protocol 2), no transport header
    if (!p || p->protocol != 2 || p->payload_len < 8) {
        return 0;
    }

    const uint8_t* data = p->payload;

    // IGMPv2 message types:
    // 0x11 = Membership Query
    // 0x16 = Membership Report
    // 0x17 = Leave Group
    if (data[0] != 0x11 && data[0] != 0x16 && data[0] != 0x17) return 0;

    // Byte 1 is Max Response Time — valid range is 0-255, no filtering needed
    // Bytes 2-3 are the checksum, bytes 4-7 are the group address

    p->app_protocol = 222;
    return 1;
}

int IsSSDP(packet* p) {
    // SSDP uses UDP port 1900, multicast to 239.255.255.250
    if (!p || p->protocol != 17 || p->payload_len < 16) {
        return 0;
    }

    if (p->src_port != 1900 && p->dst_port != 1900) return 0;

    const uint8_t* data = p->payload;

    // SSDP is plaintext HTTP-like. Requests start with a method,
    // responses start with "HTTP/"
    if (memcmp(data, "M-SEARCH", 8) == 0 ||
        memcmp(data, "NOTIFY", 6) == 0 ||
        memcmp(data, "HTTP/", 5) == 0) {
        p->app_protocol = 223;
        return 1;
    }

    return 0;
}