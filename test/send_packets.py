from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import send, sendp

def send_packet(protocol, dst_ip, src_ip=None, src_port=None, dst_port=None,
                src_mac=None, dst_mac=None, flags=None, num_packets=1, iface=None):
    protocol = protocol.upper()

    packets = []

    if protocol == "TCP":
        pkt = IP(dst=dst_ip)
        if src_ip:
            pkt.src = src_ip
        tcp_layer = TCP()
        if src_port:
            tcp_layer.sport = src_port
        if dst_port:
            tcp_layer.dport = dst_port
        if flags:
            tcp_layer.flags = flags
        pkt = pkt / tcp_layer
        packets = [pkt] * num_packets
        send(packets, iface=iface)

    elif protocol == "UDP":
        pkt = IP(dst=dst_ip)
        if src_ip:
            pkt.src = src_ip
        udp_layer = UDP()
        if src_port:
            udp_layer.sport = src_port
        if dst_port:
            udp_layer.dport = dst_port
        pkt = pkt / udp_layer
        packets = [pkt] * num_packets
        send(packets, iface=iface)

    elif protocol == "ICMP":
        pkt = IP(dst=dst_ip)
        if src_ip:
            pkt.src = src_ip
        pkt = pkt / ICMP()
        packets = [pkt] * num_packets
        send(packets, iface=iface)

    elif protocol == "ARP":
        if not dst_ip:
            raise ValueError("ARP requires pdst (destination IP)")
        ether_layer = Ether(dst=dst_mac if dst_mac else "ff:ff:ff:ff:ff:ff")
        arp_layer = ARP(pdst=dst_ip)
        if src_ip:
            arp_layer.psrc = src_ip
        if src_mac:
            arp_layer.hwsrc = src_mac
        pkt = ether_layer / arp_layer
        packets = [pkt] * num_packets
        sendp(packets, iface=iface)

    else:
        raise ValueError(f"Unsupported protocol: {protocol}")
    
def main():
    protocol = "UDP"
    dst_ip = "127.0.0.1"
    src_ip = "192.168.1.2"
    src_port = 12345
    dst_port = 53
    src_mac = "56:1A:7D:3F:4B:6C"
    dst_mac = "41:1A:7D:3F:4B:6C"
    flags = None
    num_packets = 1
    
    send_packet(protocol, dst_ip, src_ip, src_port, dst_port, src_mac, dst_mac, flags, num_packets)
    
    '''for port in range(40):
        send_packet(protocol, dst_ip, src_ip, src_port, port, src_mac, dst_mac, flags, num_packets)
        pass'''
    
    
main()