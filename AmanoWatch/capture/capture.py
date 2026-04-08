from capture.classes.PyPacket import PyPacket
from capture.classes.CPacket import CPacket
from capture.parse.ip import format_ip
from capture.parse.mac import format_mac
from capture.parse.flags import format_flags
from capture.parse.protocol import parse_protocol
from utils.load_dll import get_dll_path
from utils.ui_helpers import error
import ctypes


# PACKET_BATCH_SZIE acts as a ceiling. C returns early on pcap timeout (100ms),
# so on quiet links you get whatever's ready after 100ms regardless of size.
PACKET_BATCH_SIZE = 1000

# GUI sampling — only forward 1 in N packets to the CLI queue under load.
# The GUI only displays ~500 rows anyway and batches on a 60ms timer, so
# feeding it 100k pps is pure waste. Sampling kicks in automatically.
CLI_SAMPLE_THRESHOLD = 5000   # packets/sec above which we start sampling
CLI_SAMPLE_RATE_HIGH = 10     # 1 in 10 when over threshold


def convert_to_pypacket(protocol, type, flags, src_mac, dst_mac, src_ip, dst_ip,
                        src_port, dst_port, query, query_len, timestamp):
    return PyPacket(dst_mac, src_mac, protocol, type, src_ip, dst_ip,
                    src_port, dst_port, flags, query, query_len, timestamp)

def _route(arp_q, dns_q, honey_q, fast_q, slow_q, icmp_q, cli_q,
           packet: PyPacket, cli_skip: int, cli_counter: int):
    """
    Route a packet to relevant detector queues.
    Returns the updated cli_counter.
    """
    proto = packet.protocol

    if proto == "ARP":
        arp_q.put(packet)
    elif proto == "DNS":
        print(f"[DNS] src={packet.src_ip}:{packet.src_port} dst={packet.dst_ip}:{packet.dst_port} app_proto={getattr(packet, 'app_protocol', '?')} len={len(packet.query) if packet.query else 0}")
        dns_q.put(packet)
    elif proto in ("TCP", "UDP"):
        fast_q.put(packet)
        slow_q.put(packet)
        honey_q.put(packet)
    elif proto == "ICMP":
        icmp_q.put(packet)

    # Sampled CLI feed — skip entirely when cli_skip > 1
    if cli_skip <= 1 or (cli_counter % cli_skip == 0):
        cli_q.put(packet)

    return cli_counter + 1


def begin_capture(device, arp_queue, dns_queue, honey_port_queue, fast_scan_queue,
                  slow_scan_queue, icmp_queue, cli_queue, stop_event, cli_ready):
    
    PCAP_ERRBUF_SIZE = 256
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)

    dll_path = get_dll_path("capture.dll")
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError:
        error(f"DLL not found at {dll_path}")
        return

    lib.InitCapture.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.InitCapture.restype = ctypes.c_int

    # Updated signature: now takes max_count
    lib.GetNextPacketCache.argtypes = [ctypes.POINTER(CPacket), ctypes.c_int]
    lib.GetNextPacketCache.restype = ctypes.c_int

    lib.CloseCapture.argtypes = []
    lib.CloseCapture.restype = None

    if not lib.InitCapture(device, errbuf):
        error(errbuf.value.decode(errors="ignore"))
        return

    # Pre-allocated packet cache — reused across batches
    packet_array = (CPacket * PACKET_BATCH_SIZE)()

    # Adaptive GUI sampling state
    import time
    last_rate_check = time.time()
    packets_since_check = 0
    cli_skip = 1        # 1 = send everything to CLI
    cli_counter = 0

    try:
        while not stop_event.is_set() and cli_ready.is_set():
            count = lib.GetNextPacketCache(packet_array, PACKET_BATCH_SIZE)

            if count > 0:
                for i in range(count):
                    cpacket = packet_array[i]

                    src_ip = format_ip(cpacket.src_ip, cpacket.is_ipv6)
                    dst_ip = format_ip(cpacket.dst_ip, cpacket.is_ipv6)
                    flags = format_flags(cpacket.tcp_flags)
                    src_mac = format_mac(cpacket.src_mac)
                    dst_mac = format_mac(cpacket.dst_mac)
                    raw_payload = None
                    payload_len = None

                    try:
                        if cpacket.payload_len > 0:
                            raw_payload = ctypes.string_at(cpacket.payload, cpacket.payload_len)
                            payload_len = cpacket.payload_len
                    except Exception as e:
                        error(f"Failed to read payload: {e}")

                    protocol = parse_protocol(cpacket.protocol, cpacket.app_protocol)

                    pypacket = convert_to_pypacket(
                        protocol, cpacket.type, flags, src_mac, dst_mac,
                        src_ip, dst_ip, cpacket.src_port, cpacket.dst_port,
                        raw_payload, payload_len, cpacket.tv_sec)

                    cli_counter = _route(
                        arp_queue, dns_queue, honey_port_queue,
                        fast_scan_queue, slow_scan_queue, icmp_queue,
                        cli_queue, pypacket, cli_skip, cli_counter)

                packets_since_check += count

                # Recompute sample rate every ~500ms
                now = time.time()
                elapsed = now - last_rate_check
                if elapsed >= 0.5:
                    pps = packets_since_check / elapsed
                    if pps > CLI_SAMPLE_THRESHOLD:
                        cli_skip = CLI_SAMPLE_RATE_HIGH
                    else:
                        cli_skip = 1
                    packets_since_check = 0
                    last_rate_check = now

            elif count < 0:
                error(errbuf.value.decode(errors="ignore"))
                break
            # count == 0 is just a pcap timeout on a quiet link — loop continues

    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        lib.CloseCapture()