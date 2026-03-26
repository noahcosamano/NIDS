import subprocess

def get_gateway() -> str | None:
    gateway = None
    
    result = subprocess.run(["ipconfig"], capture_output=True, text=True).stdout.strip().splitlines()
    
    for line in result:
        if line.strip().startswith("Default Gateway"):
            gateway = line.split(":")[1].strip()
            
    return gateway