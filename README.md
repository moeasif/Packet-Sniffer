# Packet-Sniffer
A packet sniffer is a tool that captures and analyzes network packets in real-time. This project uses Python and the Scapy library to monitor network traffic on a specific interface.


How It Works:
  1 The script listens on a network interface (e.g., eth0).
  2 When a packet is detected, it checks if it contains an IP layer.
  3 If the packet has an IP layer, it logs the source and destination IP addresses.
  4 The captured packets are displayed in real-time.
Use Cases:
  1 Network monitoring and debugging
  2 Security analysis and intrusion detection
  3 Learning about network protocols
How to Run It:
  1 Install Scapy: pip install scapy
  2 Run the script with administrative privileges: sudo python packet_sniffer.py
  3 Change the interface name (eth0) as needed.
