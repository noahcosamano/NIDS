from capture.classes.PyPacket import PyPacket
from detect.config import DNS_WHITELIST
from database.edit import add_detection
import math
from collections import Counter


class DnsTunnel:
    """
    DNS tunneling detector.

    A DNS tunnel encodes data into subdomain labels, so tunneled queries have
    two telltale signatures:
      1. Unusually long subdomains (normal DNS is < 30 chars)
      2. High entropy in those subdomains (encoded data looks random)

    We score each query on length and entropy independently, then combine
    into a single risk value. Thresholds are tuned for base32/base64-encoded
    payloads which hover around 4.5-5.0 bits of entropy.
    """

    def __init__(self, packet_queue, alert_callback=None):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback

    def process_packet(self, packet: PyPacket):
        if not packet.payload:
            return

        domain = self._parse_dns_name(packet.payload)
        if not domain:
            return

        subdomain = self._subdomain(domain)
        if not subdomain:
            return

        # local and arpa traffic are fine
        if domain.endswith(".local") or domain.endswith(".arpa"):
            return
        # whitelist in config.py
        if any(domain.endswith(trusted) for trusted in DNS_WHITELIST):
            return

        # Strip dots when measuring — a 6-label subdomain shouldn't get penalized for having dots in it
        subdomain_no_dots = subdomain.replace(".", "")
        if not subdomain_no_dots:
            return

        sub_len = len(subdomain_no_dots)
        entropy = self._entropy(subdomain_no_dots)

        # Score: length and entropy each contribute. Normal domains are short
        # and low entropy; tunnels are long and high entropy.
        #
        #   len_score:  0 at len<=20, scales up to ~5 at len=100
        #   ent_score:  entropy bits directly (normal DNS ~2.5, tunnel ~4.5+)
        #
        # A normal query like "mail.google.com" scores ~2.5 + 0 = 2.5
        # A tunneled query scores ~4.7 + 4 = 8.7
        len_score = max(0, (sub_len - 20) * 0.1)
        ent_score = entropy
        risk = len_score + ent_score

        severity = None
        if risk >= 8.0:
            severity = "critical"
        elif risk >= 6.5:
            severity = "high"
        elif risk >= 5.5:
            severity = "medium"
        else:
            return

        self._alert(packet, domain, sub_len, entropy, risk, severity)

    def _subdomain(self, domain: str) -> str:
        """Return everything left of the registered domain (last two labels)."""
        parts = domain.rstrip(".").split(".")
        if len(parts) <= 2:
            return ""
        return ".".join(parts[:-2])

    def _entropy(self, s: str) -> float:
        """Shannon entropy in bits per character."""
        if not s:
            return 0.0
        total = len(s)
        entropy = 0.0
        for count in Counter(s).values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _parse_dns_name(self, payload: bytes) -> str:
        """
        Extract the QNAME from a DNS question section.

        Packet layout: 12-byte DNS header, then the QNAME as a sequence of
        length-prefixed labels terminated by a zero byte.
        """
        if not payload or len(payload) < 13:
            return ""

        try:
            parts = []
            i = 12  # skip DNS header
            max_iterations = 128  # safety bound against malformed packets

            while i < len(payload) and max_iterations > 0:
                max_iterations -= 1
                length = payload[i]

                if length == 0:
                    break
                if length > 63:  # labels max at 63 bytes
                    return ""
                if i + 1 + length > len(payload):
                    return ""  # truncated

                label = payload[i + 1 : i + 1 + length]
                # Strict ASCII check — any non-printable byte means this
                # isn't a valid DNS label and we shouldn't pretend it is
                try:
                    decoded = label.decode("ascii")
                except UnicodeDecodeError:
                    return ""
                if not all(32 <= b < 127 for b in label):
                    return ""

                parts.append(decoded)
                i += 1 + length

            return ".".join(parts)
        except Exception:
            return ""

    def _alert(self, packet: PyPacket, domain: str, sub_len: int,
               entropy: float, risk: float, severity: str):
        summary = f"{packet.src_ip} queried suspicious domain (possible DNS tunnel)"
        details = (
            f"Domain: {domain}\n"
            f"Subdomain length: {sub_len}\n"
            f"Entropy: {entropy:.2f} bits\n"
            f"Risk score: {risk:.2f}"
        )

        if self.alert_callback:
            self.alert_callback(
                severity,
                "DNS TUNNELING",
                f"High-entropy domain from {packet.src_ip}: {domain[:80]}"
            )

        add_detection(
            detector_type="DNS Tunnel",
            severity=severity,
            summary=summary,
            src_ip=packet.src_ip,
            src_mac=packet.src_mac,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_mac=packet.dst_mac,
            dst_port=packet.dst_port,
            details=details,
        )


def detect_dns_tunnel(packet_queue, stop_event, cli_ready, alert_callback=None):
    detector = DnsTunnel(packet_queue, alert_callback=alert_callback)

    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()