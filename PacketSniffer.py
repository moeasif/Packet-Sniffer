import scapy.all as scapy
import logging

# Configure logging
logging.basicConfig(filename='packet_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        log_message = f"[+] Packet: {src_ip} -> {dst_ip}"
        print(log_message)
        logging.info(log_message)

def start_sniffing(interface, filter_protocol=None):
    print(f"[*] Starting packet sniffing on {interface}...")
    if filter_protocol:
        scapy.sniff(iface=interface, store=False, prn=packet_callback, filter=filter_protocol)
    else:
        scapy.sniff(iface=interface, store=False, prn=packet_callback)

if __name__ == "__main__":
    interface = "eth0"  # Change this based on your system
    protocol_filter = "tcp"  # Change or set to None to capture all traffic
    start_sniffing(interface, protocol_filter)