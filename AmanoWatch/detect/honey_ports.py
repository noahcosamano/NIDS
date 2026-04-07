from detect.config import HONEY_PORTS
from capture.classes.PyPacket import PyPacket
from database.add_detection import add_detection
from network.block_ip import block_ip, unblock_ip
from network.get_gateway import get_gateway
from network.get_ip import get_ip
from utils.geolocate_ip import search_ip

class HoneyPort:
    def __init__(self, device, packet_queue, alert_callback=None):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback
        self.gateway = get_gateway()
        self.host_ip = get_ip(device)
        
        if self.host_ip:
            self.host_ip = self.host_ip.replace("(Preferred)","").strip()
        
    def _process_packet(self, packet: PyPacket):
        now = packet.timestamp
        dst_port = packet.dst_port
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        
        if not src_ip or not dst_port or not dst_ip:
            return
        
        if dst_ip != self.host_ip:
            return
        
        if src_ip == self.host_ip or src_ip == self.gateway or src_ip.startswith("127."):
            return
        
        protocol, reason = self.check_port(dst_port)
        
        if protocol and reason:
            self.detect(packet, protocol, reason)
        
    def check_port(self, dst_port):
        if dst_port in HONEY_PORTS.keys():
            protocol = HONEY_PORTS[dst_port].get("protocol")
            reason = HONEY_PORTS[dst_port].get("reason")
            
            #print(f"Protocol: {protocol} | Reason: {reason}")
            
            return protocol, reason
        
        return None, None
    
    def detect(self, packet: PyPacket, protocol, reason):
        country = search_ip(packet.src_ip) or "Unknown"

        summary = f"{packet.src_ip} connected to port {packet.dst_port}"
        details = f"Origin: {country}, Port Protocol: {protocol}, Reason for Flag: {reason}"

        add_detection(
            detector_type="Honey Port",
            severity="INFO",
            summary=summary,
            src_ip=packet.src_ip,
            src_mac=packet.src_mac,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_mac=packet.dst_mac,
            dst_port=packet.dst_port,
            details=details,
        )

        if self.alert_callback:
            self.alert_callback(
                "info",
                "Honeyport Connection Established",
                f"{packet.src_ip} (origin: {country}) connected to port {packet.dst_port}\n"
                f"port {packet.dst_port} is generally used for {protocol}\n"
                f"Reason for alert: {reason}"
            )
        
def detect_honey_port_connection(device_name, packet_queue, stop_event, cli_ready, alert_callback=None):
    detector = HoneyPort(device_name, packet_queue, alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        unblock_ip()
        packet: PyPacket = packet_queue.get()
        try:
            detector._process_packet(packet)
        finally:
            packet_queue.task_done()