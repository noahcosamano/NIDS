import subprocess
from utils.ui_helpers import error

def get_ip(device_name: str) -> str:
    """This function returns the IPv4 address of a given device name, useful
    for detecting when a packet is an inbound or outbound packet.

    Args:
        device_name (str): tells the function the device to get the address from

    Returns:
        str: IPv4 on the device chosen
    """
    result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True).stdout.strip().splitlines()
    
    in_device = False # Tracks if the device being parsed is the one to search
    
    for line in result:
        if line.strip().startswith("Description"):
            device = line.split(":")[-1].strip()
            in_device = (device == device_name)
            
        if line.strip().startswith("IPv4 Address") and in_device == True:
            ip = line.split(":")[1].strip()
            return ip
        
    return None