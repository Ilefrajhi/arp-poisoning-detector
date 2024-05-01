import scapy.all as scapy
import time
import logging

logging.basicConfig(filename='arp_dos.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def set_monitor_mode(interface):
    scapy.os.system(f"sudo ifconfig {interface} down")
    scapy.os.system(f"sudo iwconfig {interface} mode monitor")
    scapy.os.system(f"sudo ifconfig {interface} up")

def detect_arp_dos(interface="wlx00873450464c", packet_count=0, threshold=0.9):
    print("[+] Setting up monitor mode...")
    set_monitor_mode(interface)
    time.sleep(2)  # Give some time for the interface to switch mode

    print("[+] Starting continuous ARP packet capture...")
    logging.info("Starting continuous ARP packet capture...")

    try:
        while True:
            packets = scapy.sniff(count=packet_count, filter="arp", iface=interface, timeout=10)  # Increase timeout to 10 seconds
            total_packets = len(packets)

            if total_packets > packet_count * threshold:
                print("[!] Excessive ARP traffic detected. Possible ARP poisoning.")
                logging.warning("Excessive ARP traffic detected. Possible ARP poisoning.")

                # Extract and display the source MAC and IP addresses of the ARP packets
                source_mac_ips = [(packet[scapy.ARP].hwsrc, packet[scapy.ARP].psrc) for packet in packets]

                if source_mac_ips:
                    print("[+] Source MAC and IP addresses triggering the ARP DoS attack:")
                    for mac, ip in set(source_mac_ips):  # Display unique MAC-IP pairs
                        print(f"MAC: {mac}, IP: {ip}")
                else:
                    print("[+] No source MAC and IP addresses found.")
            else:
                print("[+] No signs of ARP poisoning.")
                logging.info("No signs of ARP poisoning.")

            time.sleep(30)  # Increase sleep interval to 30 seconds

    except KeyboardInterrupt:
        print("[+] Stopping ARP packet capture...")
        logging.info("Stopping ARP packet capture.")

if __name__ == "__main__":
    detect_arp_dos()
