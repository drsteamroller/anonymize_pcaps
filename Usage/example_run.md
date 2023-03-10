# PCAP Scrub Examples

## Files:

- Local_example/local_traffic.pcap
  - Used to demonstrate the -sPIP option, which scrambles private IPs

The following files used are from https://wiki.wireshark.org/SampleCaptures

- HTTP_example/simple_HTTP.pcap -> A simple HTTP request and response
  - Used to demonstrate basic IP & MAC scramble, as well as a --scrub-payload option

- ARP_example/arp-storm.pcap -> Sample ARP traffic
  - Used to demonstrate ARP traffic scrambling

As the pcapsrb.py program gets update, updated modified versions of these pcaps will be uploaded. Additionally, this document will be updated to describe different implemented behaviors.

## local_traffic.pcap

**Example 1: Default Behavior**
This pcap file has a couple different types of traffic, including ICMP, Syslog, NTP, etc. It isn't fully representative of a corporate or federal environment, but this demonstration is mainly to show the private IP scrubbing capability. This was implemented as an optional flag when running the program for customers that don't want to expose any internal information that would aide a possible reconaissance into their environment. By default, any RFC 1918 Class A, B & C IP addresses are ignored when the script is run with no -sPIP (or --scrable-priv-ips) flag.

The first run of `python pcapsrb.py local_traffic.pcap` outputs the follow files:
- local_traffic_mod_def.pcap <--------- Scrubbed pcap
- local_traffic_mpdaddr_def.txt <------ Mapped address log. Every original IP/MAC address replaced shows up here mapped to the new value

If you view the original and \_mod\_def pcaps side by side, you'll see right away that the first two packets are unchanged. The default behavior of this program does not change private IPs, nor will those IPs show up in the \_mpdaddr\_def.txt file.

Notes on the following packets:

Packet No. 3 & 4:
- In the Ethernet frame, you can see the MAC addresses have been scrambled
  - This is consistent between packets 3 & 4. Check the src and dst MAC addresses

Packet No. 9:
- Notice the broadcast destination doesn't change between original and scrubbed pcaps. This is the same for IP broadcast traffic.

Packet No 16:
- The payload is not touched if you don't specificy -sp or --scrub-payload.

***
- In local_traffic_mpdaddr_def.txt file, you can see the direct mappings between MAC & IP addresses between the original and mapped pcaps.

***

**Example 2: --scrub-priv-ips/-sPIP option enabled**

`python pcapsrb.py local_traffic.pcap -sPIP`

Output Files: local_traffic_mod_spip.pcap and local_traffic_mpdaddr_spip.txt.

Same original file, now we're scrambling private IP addresses. You can't tell subnet masks via pcaps, so it is an unintellegent scramble. ~~At some point it'll choose an address within the same (assumed) /16 or /24 subnet, but for now it scrambles it the same way it would a routable address.~~** Now assumes /16 and scrambles the lower 2 bytes.

Notes on the packets:

You can now see that the 10.x addresses are now scrambled, and the mpdaddr file has grown accordingly.
***
## simple_HTTP.pcap

`python pcapsrb.py simple_HTTP.pcap -sp`

Output Files: simple_HTTP_mod.pcap and simple_HTTP_mpdaddr.txt

The way to scrub an entire payload is with the -sp option. It randomly masks every bit past the TCP/UDP header portion of a packet. It's planned for (the most) sensitive protocols to be identified and scrubbed a little more intelligently.

Notes on the following packets:

Packet No. 4:

Looks at how the -sp option bombs the HTTP GET request. Any >Layer 4 protocol will be overwritten. The overwriting starts at the 'TCP payload' section of the packet, preserving any src/dst ports for troubleshooting problems. 

Packet No. 13:

Here we can see the -sp option in action with a UDP packet. Wireshark even flags it as a malformed packet. There is no checksum recalculation or identification of most protocols past TCP/UDP.

Packet No. 36 & 37:

As the TCP/UDP header info is kept, certain packets like these spurious retransmission/duplicate ACK packets can still be identified by Wireshark expert analysis.

The -sp option should be used sparingly at this time, as it will most likely mask important troubleshooting data.
***
## arp-storm.pcap

`python pcapsrb.py arp-storm.pcap`

Output Files: arp-storm_mod.pcap and arp-storm_mpdaddr.txt

Here we can see the mapped addresses in action, where it's able to insert the same mapped address info from Ethernet frames & IP packets into ARP frames. There isn't any IP packets in this example, but if there were, the replacement would be consistent.

Notes on packets:

Notice again how broadcast traffic is not masked. The sender MAC address in the ARP packet and the src MAC in the ethernet frame are consistent as well.
***

Final notes on the program:

During runtime, the program outputs this:

"Entering pcap................."

- Entering pcap is when it starts to parse through packets. Each period '.' represents one packet parsed through, this is for debugging to pick out packets that cause problems in the program or are unrepresented in the program. If we were to feed a non-IP packet to the program, it will throw a warning that looks like this:

Packet at timestamp: {timestamp} is of non IP Packet type, therefore unsupported (as of right now)
data: {data}

It gives you the timestamp, but the period count might make it easier to ID which packet is causing the problem.

Some of the flags are not used in these examples. Some of them are self-explanatory.

-pm, --preserve-macs: turns off MAC address scramble. The original MAC addresses will appear in the scrubbed file

-pi, --preserve-ips: same as -pm, but with IP addresses

-O=<OUTFILE>: Change the name of the \*mpdaddr.txt output log file