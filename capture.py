from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from packet import Packet
from queue import Queue

protocol_nums = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def handle(raw_pkt, packet_queues: list[Queue[Packet]]):
    if IP not in raw_pkt:
        return

    # MAC (safe)
    src_mac = raw_pkt[Ether].src if Ether in raw_pkt else None
    dst_mac = raw_pkt[Ether].dst if Ether in raw_pkt else None

    # IP
    src_ip = raw_pkt[IP].src
    dst_ip = raw_pkt[IP].dst
    protocol = protocol_nums.get(raw_pkt[IP].proto, "OTHER")

    # Defaults
    src_port = None
    dst_port = None
    flags = None

    # Transport layer handling
    if TCP in raw_pkt:
        src_port = raw_pkt[TCP].sport
        dst_port = raw_pkt[TCP].dport
        flags = get_flags(raw_pkt)

    elif UDP in raw_pkt:
        src_port = raw_pkt[UDP].sport
        dst_port = raw_pkt[UDP].dport

    elif ICMP in raw_pkt:
        pass  # no ports

    pkt = Packet(
        dst_mac, src_mac, protocol,
        src_ip, dst_ip,
        src_port, dst_port, flags
    )
    
    print(pkt)

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

def capture(interface: str, pkt_queues: list[Queue[Packet]]):
    print("Capture Started.")
    sniff(
        iface=interface,
        filter="ip",
        prn=lambda pkt: handle(pkt, pkt_queues),
        store=0
    )