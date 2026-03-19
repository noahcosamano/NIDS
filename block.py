import subprocess

def block_ip(ip):
    print(f"Blocking IP: {ip}")

    subprocess.run([
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name=Block_{ip}",
        "dir=in",
        "action=block",
        f"remoteip={ip}"
    ])