import subprocess
import time

blocked_ips = {}
blocked_macs = {}

def block_ip(ip, timeout = 300):
    now = time.time()
    
    if ip in blocked_ips and blocked_ips[ip] > now:
        print(f"{ip} already blocked")
        return
    
    rule_name = f"Block_{ip}"
        
    result = subprocess.run(
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Failed:", result.stderr)
        return

    print(f"Blocked {ip} for {timeout} seconds")

    blocked_ips[ip] = now + timeout
    
def unblock_ip():
    now = time.time()

    for ip in list(blocked_ips.keys()):
        if blocked_ips[ip] <= now:
            rule_name = f"Block_{ip}"

            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ],
                capture_output=True,
                text=True
            )

            print(f"Unblocked {ip}")
            del blocked_ips[ip]
            
def block_mac(mac, timeout=300):
    now = time.time()
    mac = mac.upper()
    
    if mac in blocked_macs and blocked_macs[mac] > now:
        print(f"{mac} already blocked")
        return
    
    rule_name = f"Block_MAC_{mac}"
    
    # Add MAC filter using netsh
    result = subprocess.run(
        [
            "netsh", "wlan", "add", "filter",
            "permission=deny",
            f"mac={mac}",
            f"name={rule_name}"
        ],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print("Failed:", result.stderr)
        return
    
    print(f"Blocked MAC {mac} for {timeout} seconds")
    blocked_macs[mac] = now + timeout

def unblock_mac():
    """
    Unblocks MACs whose timeout has expired.
    """
    now = time.time()
    for mac in list(blocked_macs.keys()):
        if blocked_macs[mac] <= now:
            rule_name = f"Block_MAC_{mac}"
            
            subprocess.run(
                [
                    "netsh", "wlan", "delete", "filter",
                    f"mac={mac}",
                    "permission=deny"
                ],
                capture_output=True,
                text=True
            )
            
            print(f"Unblocked MAC {mac}")
            del blocked_macs[mac]