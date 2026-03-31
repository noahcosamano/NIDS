import requests
import os
import sys

WEBHOOK_URL = "https://discord.com/api/webhooks/1487319812026798140/6xQQHqux3fM2GoFXw9lWsSSce0ln5z2POw-1NW0s2dUrH9-tv0MhGZZXo2N5i51gWQ3F"

if getattr(sys, 'frozen', False):
    # If running as an EXE
    base_path = os.path.dirname(sys.executable)
else:
    # If running as a normal script
    base_path = os.path.dirname(os.path.abspath(__file__))

# Create the full path
log_dir = os.path.join(base_path, "logs")
log_file = os.path.join(log_dir, "command_log.txt")
    
def report_to_webhook(detection_type, content):
    content_str = str(content)

    data = {
        "username": "NIDS",
        "avatar_url": "https://fbi.cults3d.com/uploaders/40342033/illustration-file/9993ed82-301c-4ad4-8f63-4597b8337458/le%C3%B1ador-clash.png",
        "embeds": [
            {
                "title": str(detection_type),
                "description": content_str,
                "color": 16711680, # Red
                "author": {
                    "name": "Network Intrusion Detection System" # Must be an object with a 'name' key
                },
            }
        ]
    }
    
    try:
        # Using json=data automatically sets Content-Type: application/json
        response = requests.post(WEBHOOK_URL, json=data, timeout=5)
        
        if response.status_code == 204:
            pass
        else:
            print(f"Failed to send message: {response.status_code}")
            print(f"Response Body: {response.text}") # This tells you EXACTLY what is wrong
    except Exception as e:
        print(f"Webhook connection error: {e}")