from scapy.all import ARP, Ether, srp
import tkinter as tk
from threading import Thread
import datetime

class MACAddressSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("MAC Address Sniffer")
        
        self.text_area = tk.Text(root, height=15, width=100)
        self.text_area.pack()

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

    def scan_network(self):
        # Define the target network (Change this to your network if necessary)
        target_ip = "192.168.1.1/24"  # Example for typical home networks
        # Create an ARP request to discover devices
        arp_request = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        packet = ether / arp_request
        
        # Send the packet and receive the response
        result = srp(packet, timeout=2, verbose=False)[0]
        
        # Process the responses
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        # Display the devices
        self.display_devices(devices)

    def display_devices(self, devices):
        self.text_area.delete(1.0, tk.END)  # Clear the text area
        self.text_area.insert(tk.END, "IP Address\t\tMAC Address\n")
        self.text_area.insert(tk.END, "-" * 50 + "\n")
        
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            self.text_area.insert(tk.END, f"{ip}\t\t{mac}\n")

    def start_sniffing(self):
        Thread(target=self.scan_network).start()

# Create the main window
root = tk.Tk()
sniffer = MACAddressSniffer(root)
root.mainloop()
