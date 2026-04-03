def format_mac(mac_array):
    # Converts 6-byte u_char array into '00:11:22:33:44:55'
    return ":".join(f"{b:02x}" for b in mac_array)