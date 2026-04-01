from network.get_devices import get_devices
from utils.ui_helpers import error, clear

def select_device():
    devices: str = get_devices()
    device_indices = dict()
    
    if not devices:
        clear()
        error("No devices found")
        return
    
    while True:
        for index, device in enumerate(devices.strip("|").split("|"), start=1):
            device_indices[index] = device
            print(f"{index}.) {device}")
            
        try:
            selected = int(input("\nEnter a device number to capture on: "))
            
            if selected in device_indices.keys():
                device_full_string = device_indices.get(selected)
                
                adapter_path = device_full_string.split(" ")[0]
                
                start = device_full_string.find("(") + 1
                end = device_full_string.rfind(")")
                human_name = device_full_string[start:end]
                
                clear()
                return adapter_path, human_name
            
            else:
                clear()
                error("Invalid device index\n")
            
        except:
            clear()
            error("Please enter device index\n")
        
