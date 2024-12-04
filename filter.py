import pyshark
from datetime import datetime

def extract_mdns_details(pcap_file):
    """
    Extract MDNS advertised service names, hostnames, and their MAC addresses from a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.
    """
    # Filter only MDNS traffic on UDP port 5353
    capture = pyshark.FileCapture(pcap_file, display_filter="udp.port == 5353")
    devices = {}

    print("\nExtracting MDNS Details (Service Name, Hostname, MAC Address)...\n")

    for packet in capture:
        try:
            service_name = None
            hostname = None
            mac_address = None

            # Extract MDNS service name and hostname
            if 'mdns' in [layer.layer_name for layer in packet.layers]:
                mdns_layer = packet['mdns']
                
                # Get advertised services
                service_name = mdns_layer.get('dns.qry.name', None) or mdns_layer.get('dns.resp.name', None)
                if service_name and "_tcp.local" in service_name:
                    service_name = service_name.split(".")[0]  # Clean up service name

                # Get associated hostname
                hostname = mdns_layer.get('dns.resp.name', None) or mdns_layer.get('dns.qry.name', None)
                if hostname and ".local" in hostname:
                    hostname = hostname.split(".")[0]  # Clean up hostname

            # Extract MAC address
            if 'eth' in packet:  # For Ethernet traffic
                mac_address = packet.eth.src
            elif 'wlan' in packet:  # For Wi-Fi traffic
                mac_address = packet.wlan.sa

            # Filter and store details
            if mac_address and (service_name or hostname) and service_name != "_services._dns-sd._udp.local":
                devices.setdefault(mac_address, {}).setdefault('services', set())
                devices.setdefault(mac_address, {}).setdefault('hostnames', set())
                if service_name:
                    devices[mac_address]['services'].add(service_name)
                if hostname and hostname != "<Root>":
                    devices[mac_address]['hostnames'].add(hostname)

        except AttributeError as e:
            print(f"Error processing MDNS packet: {e}")

    capture.close()

    # Display results
    print("MDNS Devices Found:")
    for mac, details in devices.items():
        print(f"\nMAC Address: {mac}")
        if details['services']:
            print(f"  Services: {', '.join(details['services'])}")
        if details['hostnames']:
            print(f"  Hostnames: {', '.join(details['hostnames'])}")

def analyze_disconnect_packets(pcap_file, attack_threshold=5, attack_time_window=1):
    """
    Analyze Deauthentication and Disassociation packets in a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.
        attack_threshold (int): Number of packets within the time window to classify as an attack.
        attack_time_window (float): Time window in seconds to detect attacks.

    Returns:
        None
    """
    capture = pyshark.FileCapture(pcap_file, display_filter="wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a")
    deauth_count = 0
    disassoc_count = 0
    previous_time = None
    packet_times = []  # List to track timestamps of suspicious packets

    print("\nAnalyzing Deauthentication and Disassociation packets...\n")

    for packet in capture:
        try:
            packet_type = None
            if packet.wlan.fc_type_subtype == "0x000c":  # Deauthentication
                deauth_count += 1
                packet_type = "Deauthentication"
            elif packet.wlan.fc_type_subtype == "0x000a":  # Disassociation
                disassoc_count += 1
                packet_type = "Disassociation"

            # Extract timestamp
            current_time = packet.sniff_time
            if previous_time:
                time_diff = (current_time - previous_time).total_seconds()
                # if time_diff < attack_time_window:  # Detect if within the threshold
                    # print(f"{packet_type} Packet: Time Difference = {time_diff:.2f}s")
            previous_time = current_time

            # Log timestamps for attack analysis
            packet_times.append(current_time)

        except AttributeError as e:
            print(f"Error processing packet: {e}")

    capture.close()

    # Detect attack based on packet frequency
    attack_detected = False
    for i in range(len(packet_times) - 1):
        count_within_window = 1  # Include the current packet
        for j in range(i + 1, len(packet_times)):
            if (packet_times[j] - packet_times[i]).total_seconds() <= attack_time_window:
                count_within_window += 1
            else:
                break
        if count_within_window >= attack_threshold:
            attack_detected = True
            break

    # Summary
    print("\nSummary:")
    print(f"Total Deauthentication Packets: {deauth_count}")
    print(f"Total Disassociation Packets: {disassoc_count}")
    if attack_detected:
        print("Potential attack detected based on packet frequency!")
    else:
        print("No attack detected based on the given thresholds.")


def extract_access_points(pcap_file):
    """
    Extract access point details (BSSID, SSID, signal strengths) from a PCAP capture.

    Args:
        pcap_file (str): Path to the PCAP file.

    Returns:
        None
    """

    capture = pyshark.FileCapture(pcap_file, display_filter="wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01 || wlan.fc.type_subtype == 0x08")
    ap_data = {}
    connected_devices = {}

    print("\nExtracting Access Points...\n\nListing Connected Devices...\n")

    for packet in capture:
        try:
            # Extract signal strength
            signal_strength = None
            if 'wlan_radio' in packet:
                signal_strength = packet.wlan_radio.signal_dbm

            # Extract BSSID, SSID, and Signal Strength
            if 'wlan.mgt' in [layer.layer_name for layer in packet.layers]:
                wlan_mgt_layer = packet['wlan.mgt']
                tim_info = packet['wlan.mgt'].get('wlan_tim_partial_virtual_bitmap', None)
                bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else "Unknown"
                ssid_hex = wlan_mgt_layer.get('wlan_ssid', None)
                if ssid_hex:
                    try:
                        ssid_bytes = bytes.fromhex(ssid_hex.replace(":", ""))
                        ssid = ssid_bytes.decode("ascii")
                    except Exception:
                        ssid = "<Invalid SSID>"
                else:
                    ssid = "<Hidden SSID>"
                
                # Add to the dictionary
                ap_key = (bssid, ssid)
                if ap_key not in ap_data:
                    ap_data[ap_key] = set()  # Use a set to store unique signal strengths
                if signal_strength is not None:
                    ap_data[ap_key].add(signal_strength)

                if tim_info:  # Asleep devices
                    tim_bits = bytes.fromhex(tim_info.replace(":", ""))
                    for aid, bit in enumerate(tim_bits):
                        if bit:
                            connected_devices.setdefault(bssid, {}).setdefault('asleep', set()).add(f"AID {aid}")

            if 'wlan' in packet:
                source_mac = packet.wlan.sa if hasattr(packet.wlan, 'sa') else "Unknown"
                destination_mac = packet.wlan.da if hasattr(packet.wlan, 'da') else "Unknown"
                bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else "Unknown"

                if source_mac != bssid and destination_mac == bssid:  # Active devices
                    connected_devices.setdefault(bssid, {}).setdefault('active', set()).add(source_mac)

        except AttributeError as e:
            print(f"Error processing packet: {e}")

    capture.close()

    # Print all APs
    print("Access Points Found:")
    for (bssid, ssid), signal_strengths in ap_data.items():
        print(f"AP MAC: {bssid}, SSID: {ssid}")
        print(f"  Signal Strengths: {', '.join(map(str, signal_strengths))} dBm")

    for bssid, devices in connected_devices.items():
        print(f"\nAP MAC: {bssid}")
        if 'asleep' in devices:
            print(f"  Asleep Devices: {', '.join(devices['asleep'])}")
        if 'active' in devices:
            print(f"  Active Devices: {', '.join(set(devices['active']))}")


def main():
    # Path to the PCAP file
    # pcap_file_disconnected = "pcap/attacked.pcap"  # Replace with your PCAP file path
    pcap_file_ap = "pcap/active.pcap"
    # pcap_file_filter = "pcap/filter.pcap"

    # Network credentials (not needed for access point extraction or disconnect analysis)
    ssid = "Searching for Wifi"  # Replace with your network SSID
    password = ""  # Replace with your network password

    # Parameters for attack detection
    attack_threshold = 5  # Minimum number of packets to classify as an attack
    attack_time_window = 1  # Time window (in seconds) to detect attacks

    # Analyze deauthentication and disassociation packets
    analyze_disconnect_packets(pcap_file_ap, attack_threshold, attack_time_window)

    # Extract access point details
    extract_access_points(pcap_file_ap)
    extract_mdns_details(pcap_file_ap)


if __name__ == "__main__":
    main()



