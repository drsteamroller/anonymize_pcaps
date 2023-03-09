# PCAP Scrub Example

## Files:

- Local_example/local_traffic.pcap
  - Used to demonstrate the -sPIP option, which scrambles private IPs

The following files used are from https://wiki.wireshark.org/SampleCaptures

- HTTP_example/simple_HTTP_rxtx.pcap -> A simple HTTP request and response
  - Used to demonstrate basic IP & MAC scramble, as well as a --scrub-payload option

- ARP_example/arp-storm.pcap -> Sample ARP traffic
  - Used to demonstrate ARP traffic scrambling

As the pcapsrb.py program gets update, updated modified versions of these pcaps will be uploaded. Additionally, this document will be updated to describe different implemented behaviors.

## local_traffic.pcap
This pcap file has a couple different types of traffic, including ICMP, Syslog, NTP, etc. It isn't fully representative of a corporate or federal environment, but this demonstration is mainly to show the private IP scrubbing capability. This was implemented as an optional flag when running the program for customers that don't want to expose any internal information that would aide a possible reconaissance into their environment. By default, any RFC 1918 Class A, B & C IP addresses are ignored when the script is run with no -sPIP (or --scrable-priv-ips) flag.

The first run of `python pcapsrb.py local_traffic.pcap` outputs the follow files:
- local_traffic_mod_def.pcap <--------- Scrubbed pcap
- local_traffic_mpdaddr_def.txt <------ Mapped address log. Every original IP/MAC address replaced shows up here mapped to the new value

If you view the original and \_mod\_def pcaps side by side, you'll see right away that the first two packets are unchanged. The default behavior of this program does not change private IPs, nor will those IPs show up in the \_mpdaddr\_def.txt file.

Notes on the following packets:

Packet No. 3 & 4:
- In the Ethernet frame, you can see the MAC addresses have been scrambled
  - This is consistent between packets 3 & 4. Check the 

TODO

## simple_HTTP_rxtx.pcap

TODO

## arp-storm.pcap

TODO