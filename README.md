# Wifi-Sniffing

## Objective
Our objective is to configure a USB network adapter in monitor mode and analyze the network activities of the host adapter, focusing on the interactions between the Wi-Fi access point (AP) and the local area network (LAN).
## Overview
This project analyzes decrpyted Wifi network traffic by processing PCAP files to extract key details about access points, connected devices, potential attacks, and advertised services in a local Wi-Fi environment. <br>

### Flow
Capture -> Decrypt -> Process -> Analyze -> Summarize -> Results

### What do we anaylze?
1. MAC, SSID, and Signal of Access Point <br>

   BSSID (MAC address), SSID (network name), and signal strengths from management layer in Beacon Frames.
   
3. Connected Devices with AP <br>

   Devices actively communicating with or sleeping (asleep) in relation to the access points from Association and Reassociation Frames and TIM (Traffic Indication Map) Field in Beacon Frames.

4. Potential attack <br>

   We will processes a PCAP file to analyze Deauthentication and Disassociation packets, which are often associated with Wi-Fi attacks like deauthentication floods. Then uses PyShark to filter and count these packet types, tracks their timestamps, and identifies potential attacks based on packet frequency within a configurable time window.
   
5. Service Name and Hostname <br>

   We will parses a PCAP file to extract Multicast DNS (mDNS) details. Then identifies and displays advertised service names, hostnames, and associated MAC addresses from mDNS traffic (UDP port 5353).
   
## Setup Hardware and System Configuration
### Operating System, USB Network Adapter, and Driver
- Operating System <br> Kali Linux 2024.4 <br><br>
- USB Network Adaptor <br> AWUS036ACM / AWUS036ACHM <br><br>
- Chipset/Driver <br> Mediatek/mt76x0u <br><br>

Since the mt76x0u and 88XXau drivers are pre-installed in Kali Linux, I simply plugged in the adapter, and it worked seamlessly. <br> 
However, if you are using a different operating system, adapter, or driver, ensure that your hardware is compatible and the appropriate drivers are installed. <br>
(Linux-based operating systems are highly recommended for better compatibility and support.)

### Set USB Adapter to Monitor Mode
1. Check Adapter Name
```
iwconfig
```
2. Set Fixed Adapter Name <br><br>
Repeatedly plugging in or unplugging the adapter may cause its name to change. To prevent this and maintain consistent control, we disable NetworkManager's management of the device, enabling manual configuration.
```
sudo nmcli dev set wlan1 managed no
```
3. Set to Monitor Mode
```
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

This is the output if it is set successfully.
```
┌──(annie㉿DESKTOP-HS4THII)-[~]
└─$ iwconfig
lo        no wireless extensions.

wlan0     IEEE 802.11  ESSID:"Searching for Wifi"  
          Mode:Managed  Frequency:5.18 GHz  Access Point: D8:EC:5E:F6:F7:AF   
          Bit Rate=263.3 Mb/s   Tx-Power=23 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          Link Quality=58/70  Signal level=-52 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:5079   Missed beacon:0

docker0   no wireless extensions.

wlan1     IEEE 802.11  Mode:Monitor  Frequency:5.18 GHz  Tx-Power=18 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:off

```
4. Match USB Adapter Channel with Host Network Adapter <br><br>
Since the host adapter (wlan0) indicates "Frequency: 5.18 GHz," we need to set it to Channel 36 to match the current frequency.

```
sudo iw dev wlan1 set channel 36
```
```
┌──(annie㉿DESKTOP-HS4THII)-[~]
└─$ iwlist wlan1 channel
wlan1     32 channels in total; available frequencies :
          Channel 01 : 2.412 GHz
          Channel 02 : 2.417 GHz
          Channel 03 : 2.422 GHz
          Channel 04 : 2.427 GHz
          Channel 05 : 2.432 GHz
          Channel 06 : 2.437 GHz
          Channel 07 : 2.442 GHz
          Channel 08 : 2.447 GHz
          Channel 09 : 2.452 GHz
          Channel 10 : 2.457 GHz
          Channel 11 : 2.462 GHz
          Channel 36 : 5.18 GHz
          Channel 40 : 5.2 GHz
          Channel 44 : 5.22 GHz
          Channel 48 : 5.24 GHz
          Channel 52 : 5.26 GHz
          Channel 56 : 5.28 GHz
          Channel 60 : 5.3 GHz
          Channel 64 : 5.32 GHz
          Channel 100 : 5.5 GHz
          Channel 104 : 5.52 GHz
          Channel 108 : 5.54 GHz
          Channel 112 : 5.56 GHz
          Channel 116 : 5.58 GHz
          Channel 120 : 5.6 GHz
          Channel 124 : 5.62 GHz
          Channel 128 : 5.64 GHz
          Channel 132 : 5.66 GHz
          Channel 136 : 5.68 GHz
          Channel 140 : 5.7 GHz
          Channel 144 : 5.72 GHz
          Channel 149 : 5.745 GHz
          Current Frequency:5.18 GHz (Channel 36)

```
### Capture EAPOL Packets

EAPOL (Extensible Authentication Protocol Over LAN) packets contain handshake encryption data required to decrypt encrypted Wi-Fi traffic in a PCAP file. Therefore, it is necessary to disconnect the connection between the access point (AP) and the host device, then reconnect to capture the handshake packets.


* How to bserve whether packets could be decrypted by Wireshark? <br>
   Edit -> Preference -> Protocols -> IEEE 802.11 -> Enable decryption (v) + Decryption keys [Edit...] -> [+] wpa-pwd | password:ssid

## Setup Wifi-Sniffing Python Environment
```
sudo apt install python3-venv
python3 -m venv ~/scapy_env
source ~/scapy_env/bin/activate
pip install scapy
pip install pyshark
```

Analyze Output
```
┌──(scapy_env)─(annie㉿DESKTOP-HS4THII)-[~/Documents/Wifi-Sniffing]
└─$ ~/scapy_env/bin/python3 ./filter.py


Analyzing Deauthentication and Disassociation packets...


Summary:
Total Deauthentication Packets: 2118
Total Disassociation Packets: 0
Potential attack detected based on packet frequency!

Extracting Access Points...

Listing Connected Devices...

Access Points Found:
AP MAC: d8:ec:5e:f6:f7:af, SSID: Searching for Wifi
  Signal Strengths: -31, -52, -48, -49, -46, -47, -40, -50, -51 dBm
AP MAC: de:ec:5e:f6:f7:af, SSID: Leeches
  Signal Strengths: -52, -48, -49, -46, -47, -50, -51 dBm
AP MAC: d8:ec:5e:f7:cd:03, SSID: Searching for Wifi
  Signal Strengths: -56, -54, -53, -55, -57 dBm
AP MAC: de:ec:5e:f7:cd:03, SSID: Leeches
  Signal Strengths: -56, -54, -53, -55, -57 dBm
AP MAC: d8:ec:5e:f6:f7:af, SSID: <Hidden SSID>
  Signal Strengths: -49, -51 dBm

AP MAC: d8:ec:5e:f6:f7:af
  Asleep Devices: AID 0
  Active Devices: 5c:ba:ef:5c:51:db, e6:b0:2b:c8:d7:b0

AP MAC: d8:ec:5e:f7:cd:03
  Asleep Devices: AID 0

Extracting MDNS Details (Service Name, Hostname, MAC Address)...

MDNS Devices Found:

MAC Address: 86:43:6a:be:76:b8
  Services: CLink-45b83532d72a
  Hostnames: CLink-45b83532d72a

MAC Address: 5c:ba:ef:5c:51:db
  Services: _googlecast
  Hostnames: _googlecast

MAC Address: d8:ec:5e:f7:cd:02
  Services: master
  Hostnames: master

MAC Address: d8:ec:5e:f6:f7:ae
  Services: master, myrouter.local
  Hostnames: myrouter, master

MAC Address: e6:b0:2b:c8:d7:b0
  Services: _companion-link, _airplay, _raop
  Hostnames: _companion-link, _raop

MAC Address: d8:ec:5e:f7:cd:01
  Services: master
  Hostnames: master

MAC Address: d8:ec:5e:f6:f7:ad
  Services: master, myrouter.local
  Hostnames: myrouter, master

MAC Address: 22:81:de:b1:08:14
  Services: _rdlink, _companion-link
  Hostnames: _rdlink, _companion-link

MAC Address: 7e:b7:96:c7:bf:2d
  Services: _rdlink, Mishy, 6.5.0.D.6.5.C.6.1.9.6.1.6.C.8.1.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa, _companion-link
  Hostnames: _rdlink, Mishy, 6.5.0.D.6.5.C.6.1.9.6.1.6.C.8.1.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa, _companion-link
```
## Challenge and Troubleshooting
1. Operating System <br>
Initially, my laptop was running Windows 10. However, most monitor mode drivers are only supported on Linux-based operating systems. While I explored using WSL/WSL 2, they do not support enabling monitor mode. As a result, I decided to install Kali Linux to fully leverage monitor mode functionality.


1) Introduction to the problem: what's the objective and why it's important; (1-2 slides)

2) Overview: What you do on a high level (e.g., here's an end-to-end system and you build xx, yy, and/or change zz to realize your objective); If you did any literature study and/or paper analysis, present it here as well; (1-2 slides)

3) Implementation Details: Present what you have built. The used libraries, tools, etc. You could put photos of your systems or screenshots of the code you wrote; (2-4 slides, depending on how much you implemented)

4) Challenges addressed: Showcase 2-3 major obstacles in your project and how you solve them; (1 slide with a few bullet points)

5) Evaluation and Demo: Find proper metrics to demonstrate that your implementation works well. Conduct a live or recorded demo if possible, or a recorded demo; (2-3 slides)

6) Lessons learned and remaining tasks. (1 slide, serving as summary)
