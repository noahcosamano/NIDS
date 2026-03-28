from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from configurations.packet import Packet
from queue import Queue
from time import time
from configurations.proto_nums import protocol_nums
from logs.log import log_event  

def handle(raw_pkt, packet_queues: list[Queue[Packet]]):
    try:
        # 1. Safe MAC extraction
        src_mac = raw_pkt[Ether].src if Ether in raw_pkt else "00:00:00:00:00:00"
        dst_mac = raw_pkt[Ether].dst if Ether in raw_pkt else "00:00:00:00:00:00"
        
        # 2. ARP Handling (Early return)
        if ARP in raw_pkt:
            pkt = Packet(
                raw_pkt[ARP].hwdst, raw_pkt[ARP].hwsrc, "ARP",
                None, raw_pkt[ARP].psrc, raw_pkt[ARP].pdst, 
                None, None, None, None, time()
            )
            for q in packet_queues: q.put(pkt)
            return

        # 3. IP Layer Extraction
        if IP in raw_pkt:
            ip_layer = raw_pkt[IP]
            proto_id = ip_layer.proto
        elif IPv6 in raw_pkt:
            ip_layer = raw_pkt[IPv6]
            proto_id = ip_layer.nh
        else:
            return # Not an IP packet we care about

        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        protocol = protocol_nums.get(proto_id, "OTHER")

        # 4. Transport Layer Extraction
        src_port, dst_port, flags = None, None, None
        
        if TCP in raw_pkt:
            src_port, dst_port = raw_pkt[TCP].sport, raw_pkt[TCP].dport
            flags = get_flags(raw_pkt)
        elif UDP in raw_pkt:
            src_port, dst_port = raw_pkt[UDP].sport, raw_pkt[UDP].dport

        # 5. DNS Specific Logic
        query = None
        if DNS in raw_pkt:
            protocol = "DNS"
            # Only extract qname if it exists (some DNS responses don't mirror the query)
            if raw_pkt[DNS].qd:
                query = raw_pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
        elif Raw in raw_pkt:
            query = raw_pkt[Raw].load

        # 6. Final Packet Assembly
        pkt = Packet(
            dst_mac, src_mac, protocol,
            get_type(raw_pkt), src_ip, dst_ip, 
            src_port, dst_port, flags, query, time()
        )

        for queue in packet_queues:
            queue.put(pkt)

    except Exception as e:
        # This prevents one bad packet from killing your whole sniffer
        print(f"Error handling packet: {e}")

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
        sniff(
            iface=interface,
            filter="ip or arp or udp port 53 or tcp port 53", # scapy does not support dns keyword so port 53 is used
            prn=lambda pkt: handle(pkt, pkt_queues),
            store=0,
            stop_filter=lambda x: stop_event.is_set()
        )