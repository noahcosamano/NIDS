def welcome(device):
    print(" " + "═"*85)
    print(f"  DEVICE: {device} | INTRUSTION DETECTION SYSTEM STATUS: \033[92mACTIVE\033[0m")
    print(" " + "═"*85)

    print("\n\033[1mAVAILABLE COMMANDS:\033[0m")

    # Command: View
    print("\n  \033[94mview\033[0m [proto|port] \033[2m-wait=[ms]\033[0m")
    print("  └─ Stream live traffic. (e.g., 'view tcp')")

    # Command: Devices
    print("\n  \033[94mdevices\033[0m")
    print("  └─ List available network interfaces.")

    # Command: Exit
    print("\n  \033[91mexit\033[0m")
    print("  └─ Shutdown the NIDS.")

    print("\n" + "─"*87 + "\n")