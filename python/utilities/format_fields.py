import socket

def format_ip(ip_array, is_ipv6):
    """Converts raw bytes from the struct into a readable IP string."""
    try:
        if is_ipv6:
            return socket.inet_ntop(socket.AF_INET6, bytes(ip_array))
        else:
            # IPv4 only uses the first 4 bytes of the 16-byte array
            return socket.inet_ntop(socket.AF_INET, bytes(ip_array[:4]))
    except Exception:
        return "Unknown"
    
def format_mac(mac_array):
    """Converts 6-byte array to '00:11:22:33:44:55'"""
    return ":".join(f"{b:02x}" for b in mac_array)

def format_flags(flags_num):
    """Converts TCP flag byte to string (e.g., 'SYN ACK')"""
    # Standard TCP Flag bits
    res = []
    if flags_num & 0x01: res.append("FIN")
    if flags_num & 0x02: res.append("SYN")
    if flags_num & 0x04: res.append("RST")
    if flags_num & 0x08: res.append("PSH")
    if flags_num & 0x10: res.append("ACK")
    if flags_num & 0x20: res.append("URG")
    return " ".join(res) if res else None