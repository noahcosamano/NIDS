def format_flags(flags_num):
    # Converts TCP flag byte to string (e.g., 'SYN ACK')
    # Standard TCP Flag bits
    res = []
    if flags_num & 0x01: res.append("FIN")
    if flags_num & 0x02: res.append("SYN")
    if flags_num & 0x04: res.append("RST")
    if flags_num & 0x08: res.append("PSH")
    if flags_num & 0x10: res.append("ACK")
    if flags_num & 0x20: res.append("URG")
    return " ".join(res) if res else None