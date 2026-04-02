from capture.config.config import protocol_nums, tcp_service_ports, udp_service_ports

def parse_protocol(protocol_num, app_protocol_num):
    protocol = protocol_nums[protocol_num]
    if protocol == "TCP":
        protocol = tcp_service_ports.get(app_protocol_num, "TCP")
    elif protocol == "UDP":
        protocol = udp_service_ports.get(app_protocol_num, "UDP")
    elif protocol == "ARP":
        return protocol
    elif protocol == "ICMPV6":
        return protocol
    else:
        protocol = protocol_nums.get(protocol, "UNKNOWN")
        
    return protocol