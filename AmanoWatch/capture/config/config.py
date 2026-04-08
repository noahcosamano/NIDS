"""
These are all of the default IEEE protocol numbers used to convert the uint8_t format protocol
into the real human-readable protocol.
"""

protocol_nums = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPV4", 5: "ST", 6: "TCP", 
    7: "CBT", 8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 
    13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 
    19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 
    24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 
    29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 
    34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 
    40: "IL", 41: "IPV6", 42: "SDRP", 43: "IPV6-ROUTE", 44: "IPV6-FRAG", 
    45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP", 
    51: "AH", 52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP", 
    57: "SKIP", 58: "ICMPV6", 59: "IPV6-NONXT", 60: "IPV6-OPTS", 61: "ANY", 
    62: "CFTP", 63: "ANY", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 
    67: "IPPC", 68: "ANY", 69: "SAT-MON", 70: "VISA", 71: "IPCV", 72: "CPNX", 
    73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 
    78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 
    83: "VINES", 84: "TTP", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF", 88: "EIGRP", 
    89: "OSPF", 90: "SPRITE-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "IPIP", 
    95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "ANY", 100: "GMTP", 
    101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX", 
    107: "A/N", 108: "IPCOMP", 109: "SNP", 110: "COMPAQ-PEER", 111: "IPX-IN-IP", 
    112: "VRRP", 113: "PGM", 114: "ANY", 115: "L2TP", 116: "DDX", 117: "IATP", 
    118: "STP", 119: "SRP", 120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 
    124: "ISIS OVER IPV4", 125: "FIRE", 126: "CRTP", 127: "CRUDP", 
    128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 
    133: "FC", 134: "RSVP-E2E-IGNORE", 135: "MOBILITY HEADER", 136: "UDPLITE", 
    137: "MPLS-IN-IP", 138: "MANET", 139: "HIP", 140: "SHIM6", 141: "WESP", 
    142: "ROHC", 143: "ETHERNET", 205: "ARP"
}

'''
The dictionaries below are application layer protocols in which I have defined my own integer values to them
for the ease of simplicity. In the inspect.h header file used in capture.c, all protocols are parsed and these
custom integers are all assigned to the "app_protocol" field in the C packet. So a packet could have protocol
set to 6 (TCP), but app_protocol could be set to 206 (DNS). This is to maintain original protocol while still
having application layer stored.
'''

tcp_service_ports = {
    206: "DNS",
    207: "MDNS",
    208: "TLS",
    210: "TELNET",
    211: "FTP",
    213: "NFS",
    214: "SMTP",
    215: "LDP",
    218: "HTTP",
    219: "HTTPS",
    220: "POP3",        
}

udp_service_ports = {
    206: "DNS",
    207: "MDNS",
    209: "QUIC",
    212: "TFTP",
    213: "NFS",
    216: "SNMP",
    217: "DHCP",
    221: "LLMNR",
    223: "SSDP"
}