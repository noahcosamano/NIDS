from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from configurations.packet import Packet
from queue import Queue
from time import time
from configurations.proto_nums import protocol_nums
from logs.log import log_event

def handle(raw_pkt, packet_queues: list[Queue[Packet]]):
    # MAC (safe)
    src_mac = raw_pkt[Ether].src if Ether in raw_pkt else None
    dst_mac = raw_pkt[Ether].dst if Ether in raw_pkt else None
    
    if ARP in raw_pkt:
        src_mac = raw_pkt[ARP].hwsrc
        dst_mac = raw_pkt[ARP].hwdst
        src_ip = raw_pkt[ARP].psrc
        dst_ip = raw_pkt[ARP].pdst
        protocol = "ARP"

        pkt = Packet(
            dst_mac, src_mac, protocol,
            None, src_ip, dst_ip,
            None, None, None, time()
        )

        for queue in packet_queues:
            queue.put(pkt)

        return

    if IP in raw_pkt:
        ip_layer = raw_pkt[IP]
    elif IPv6 in raw_pkt:
        ip_layer = raw_pkt[IPv6]
    else:
        return

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    proto_id = ip_layer.proto if IP in raw_pkt else ip_layer.nh
    protocol = protocol_nums.get(proto_id, "DEFAULT")

    src_port = None
    dst_port = None
    flags = None
    type = None

    # Use explicit layer access
    if TCP in raw_pkt:
        src_port = raw_pkt[TCP].sport
        dst_port = raw_pkt[TCP].dport
        flags = get_flags(raw_pkt)
    elif UDP in raw_pkt:
        src_port = raw_pkt[UDP].sport
        dst_port = raw_pkt[UDP].dport

    # Explicitly label DNS
    if src_port == 53 or dst_port == 53:
        protocol = "DNS"

    pkt = Packet(
        dst_mac, src_mac, protocol,
        type, src_ip, dst_ip, src_port, 
        dst_port, flags, time()
    )

    for queue in packet_queues:
        queue.put(pkt)

def get_flags(raw_pkt):
    if TCP in raw_pkt:
        flags = int(raw_pkt[TCP].flags)

        names = []
        if flags & 0x01: names.append("FIN")
        if flags & 0x02: names.append("SYN")
        if flags & 0x04: names.append("RST")
        if flags & 0x08: names.append("PSH")
        if flags & 0x10: names.append("ACK")
        if flags & 0x20: names.append("URG")

        return ",".join(names)
    return None

def get_type(raw_pkt):
    if ICMP in raw_pkt:
        icmp_type = raw_pkt[ICMP].type
        return icmp_type
    return None

def capture(interface: str, pkt_queues: list[Queue[Packet]], stop_event): # * Note: capture takes a list of multiple packet queue's
                                                              #   to have seperate but identical queues for each type of   
                                                              #   scan in order to prevent race conditions from occuring.
    while not stop_event.is_set():
        sniff(
            iface=interface,
            filter="ip or arp or udp port 53 or tcp port 53", # scapy does not support dns keyword so port 53 is used
            prn=lambda pkt: handle(pkt, pkt_queues),
            store=0
        )