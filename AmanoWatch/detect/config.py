# In order to process flag in scan to get scan type
FLAG_TO_NAME = {
    "SYN": "SYN Scan",
    "ACK": "ACK Scan",
    "FIN": "FIN Scan",
    "FIN PSH URG": "Xmas Scan",
    "NONE": "Null scan",
    "FIN ACK": "Maimon Scan",
}

DNS_WHITELIST = {
    "azure.com", 
    "microsoft.com", 
    "windowsupdate.com", 
    "amazonaws.com", 
    "google.com", 
    "akamai.net",
    "sharepoint.com"
}

# List of ports that usually remain silent under normal conditions
HONEY_PORTS = {
    # Legacy / Dead Protocols
    1:     {"protocol": "TCP Port Service Multiplexer (TCPMUX)",  "reason": "Obsolete, never used in modern networks, any hit is a scan"},
    2:     {"protocol": "CompressNET Management Utility",         "reason": "Obsolete, no legitimate modern use"},
    3:     {"protocol": "CompressNET Compression Process",        "reason": "Obsolete, no legitimate modern use"},
    7:     {"protocol": "Echo Protocol",                          "reason": "Used for DDoS amplification, should never see traffic"},
    19:    {"protocol": "Character Generator Protocol (CHARGEN)", "reason": "Used for DDoS amplification attacks, obsolete"},
    21:    {"protocol": "FTP (File Transfer Protocol)",           "reason": "Deprecated, attackers scan for anonymous access and writable dirs"},
    23:    {"protocol": "Telnet",                                 "reason": "Cleartext remote access, exploited heavily by Mirai botnet and others"},

    # Windows Internals
    135:   {"protocol": "Microsoft RPC Endpoint Mapper",         "reason": "Targeted for DCOM exploits, WannaCry-era attacks"},
    139:   {"protocol": "NetBIOS Session Service",               "reason": "Legacy Windows file sharing, targeted by EternalBlue and ransomware"},
    445:   {"protocol": "SMB (Server Message Block)",            "reason": "Primary vector for WannaCry, NotPetya, EternalBlue — high signal port"},
    593:   {"protocol": "RPC over HTTP",                         "reason": "Obscure Windows RPC transport, no reason to see inbound traffic"},
    5985:  {"protocol": "WinRM HTTP (Windows Remote Management)","reason": "PowerShell remoting, targeted for lateral movement"},
    5986:  {"protocol": "WinRM HTTPS",                          "reason": "Encrypted WinRM, same risk profile as 5985"},

    # Remote Access
    22:    {"protocol": "SSH (Secure Shell)",                    "reason": "Constant brute-force target — only honeyport if SSH is on a different port"},
    3389:  {"protocol": "RDP (Remote Desktop Protocol)",         "reason": "Top ransomware entry point, massively scanned and brute-forced"},
    5900:  {"protocol": "VNC (Virtual Network Computing)",       "reason": "Often misconfigured with weak/no auth, high value attacker target"},
    5901:  {"protocol": "VNC Display :1",                        "reason": "Secondary VNC display port, scanned alongside 5900"},

    # Databases
    1433:  {"protocol": "Microsoft SQL Server",                  "reason": "Targeted for credential stuffing, SQLi, and ransomware staging"},
    1521:  {"protocol": "Oracle Database",                       "reason": "Targeted for default credential attacks and TNS listener exploits"},
    3306:  {"protocol": "MySQL",                                 "reason": "Commonly exposed by misconfiguration, targeted for data exfil"},
    5432:  {"protocol": "PostgreSQL",                            "reason": "Targeted for misconfigured trust auth and credential brute-force"},
    6379:  {"protocol": "Redis",                                 "reason": "Frequently exposed with no auth, abused for RCE and cryptomining"},
    27017: {"protocol": "MongoDB",                               "reason": "Default has no auth, massive history of open database exposure"},

    # C2 / Attacker Tooling
    4444:  {"protocol": "Metasploit Default Listener",           "reason": "Classic Metasploit reverse shell port, strong indicator of compromise"},
    4445:  {"protocol": "Metasploit Alternate Listener",         "reason": "Secondary Metasploit port, same risk profile as 4444"},
    8443:  {"protocol": "Alt HTTPS / C2 over TLS",              "reason": "Used by C2 frameworks to blend with HTTPS traffic"},
    9001:  {"protocol": "Tor / Misc C2",                         "reason": "Tor relay port, also used by various C2 frameworks"},
    31337: {"protocol": "'Elite' / Back Orifice",                "reason": "Classic hacker port from Back Orifice RAT, still actively scanned"},

    # Alt HTTP
    8080:  {"protocol": "HTTP Alternate",                        "reason": "Proxy and dev server port, heavily scanned for open proxies and admin panels"},
    8888:  {"protocol": "HTTP Alternate / Jupyter",              "reason": "Jupyter notebooks often exposed here with no auth, cryptomining target"},

    # IoT / Embedded
    2323:  {"protocol": "Telnet Alternate",                      "reason": "Mirai botnet alternate Telnet port, used when 23 is filtered"},
    8291:  {"protocol": "Mikrotik Winbox",                       "reason": "Mikrotik router management, exploited by Chimay Red and similar"},
    37777: {"protocol": "Dahua DVR",                             "reason": "Dahua camera/DVR management port, targeted by IoT botnets"},
    34567: {"protocol": "Generic DVR / HiSilicon",               "reason": "Common in cheap DVR/NVR firmware, no auth by default"},

    # Container / Cloud Infrastructure
    2375:  {"protocol": "Docker Daemon (unencrypted)",           "reason": "Unauthenticated Docker API — instant RCE and host escape if exposed"},
    2376:  {"protocol": "Docker Daemon (TLS)",                   "reason": "Encrypted Docker API, still targeted for cert theft and misconfig"},
    2379:  {"protocol": "etcd Client API",                       "reason": "Kubernetes backing store, exposure leaks all cluster secrets"},
    2380:  {"protocol": "etcd Peer API",                         "reason": "etcd cluster comms port, should never be externally reachable"},
    6443:  {"protocol": "Kubernetes API Server",                 "reason": "Main K8s control plane — exposed API is full cluster compromise"},
    10250: {"protocol": "Kubelet API",                           "reason": "Node-level K8s agent, can exec into pods if exposed"},

    # UDP (monitor separately)
    69:    {"protocol": "TFTP (Trivial File Transfer Protocol)", "reason": "No auth, used for firmware uploads, abused for DDoS amplification"},
    161:   {"protocol": "SNMP (Simple Network Management Protocol)", "reason": "Default community strings leak full device info, amplification target"},
    1900:  {"protocol": "UPnP / SSDP",                          "reason": "Exploited for DDoS reflection, should never be externally visible"},

    # Special
    0:     {"protocol": "Reserved / Invalid",                    "reason": "Scanning port 0 is an OS fingerprinting technique — never legitimate"},
}

BRUTE_PORTS = {21, 22, 23, 3389, 5900, 80, 443, 8080}