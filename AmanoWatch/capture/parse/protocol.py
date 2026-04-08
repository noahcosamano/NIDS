from capture.config.config import protocol_nums, tcp_service_ports, udp_service_ports

# protocol_num: transport layer protocol e.g. 6 (TCP), 17 (UDP)
# app_protocol_num: application layer protocol e.g. 207 (MDNS)
# All app_protocol numbers are defined myself, not real IEEE standard, defaults to 0.
def parse_protocol(protocol_num, app_protocol_num):
    protocol = protocol_nums[protocol_num] # Gets string format protocol from uint8_t format from config.py
    if protocol == "TCP":
        # If a match is found in tcp_service_ports, protocol = that protocol, if not it defaults to TCP
        protocol = tcp_service_ports.get(app_protocol_num, "TCP")
    elif protocol == "UDP":
        # If a match is found in udp_service_ports, protocol = that protocol, if not it defaults to UDP
        protocol = udp_service_ports.get(app_protocol_num, "UDP")
    elif protocol == "ARP": # No special protocols for ARP
        return protocol
    elif protocol == "ICMPV6":
        return protocol
    elif protocol == "IGMP":
        return protocol
    else: # Should never happen if program is made well, all protocols should be defined.
        protocol = "UNKNOWN"
        
    return protocol