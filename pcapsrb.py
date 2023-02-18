# pcap sanitization

import sys
import dpkt
import random
import datetime

# Global Variables
ip_repl = dict()
mac_repl = dict()

# Helper functions

# Replaces IPs, but the same IP gets the same replacement
# >> I.E. 8.8.8.8 always replaces to (randomized) 144.32.109.200 in the pcap
# The point of these replacement commands is to make sure the same IP/MAC has the same replacement
def replace_ip(ip):
	# Account for broadcast
	if (ip.hex() == 'ffffffff'):
		return ip

	if (ip not in ip_repl.keys()):
		repl = ""
		for g in range(16):
			i = random.randint(0,15)
			repl += f'{i:x}'
		ip_repl[ip] = repl

		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip])

# Literally the same function as IPv4, except generates a longer address
def replace_ip6(ip6):
	# Account for broadcast	
	if (ip6.hex() == 'ffffffffffffffffffffffffffffffff'):
		return ip6

	if (ip6 not in ip_repl.keys()):
		repl = ""
		for g in range(32):
			i = random.randint(0,15)
			repl += f'{i:x}'
		ip_repl[ip6] = repl

		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip6])

# Same philosophy, but with mac addresses
def replace_mac(mac):
	# Account for broadcast
	if (mac.hex() == 'ffffffffffff'):
		return mac

	if (mac not in mac_repl.keys()):
		repl = ""
		for g in range(12):
			i = random.randint(0,15)
			repl += f'{i:x}'
		mac_repl[mac] = repl
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(mac_repl[mac])

# takes a TCP/UDP packet and determines/scrubs the data from
def scrub_upper_prots(packet):
	pass

options = {"-pi, --preserve-ips":"Program scrambles IP(v4&6) addresses by default, use this option to preserve original IP addresses","-pm, --preserve-macs":"Disable MAC address scramble","-sp, --scrub-payload":"Sanitize payload in packet (Unintelligently)"}

# Check if file is included
if (len(sys.argv) < 2):
	print("\nUsage:\n\tpcapsrb.py [file].pcap [options]\n\t--help -> for options\n")
	exit()

args = sys.argv

if ('-h' in args[1]):
	for k,v in options.items():
		print("\t{}: {}".format(k, v))
	exit()

else:
	if('.pcap' not in args[1]):
		print("Unsupported file format: \"{}\"\n", args[1])
		exit()

opflags = []

for arg in args[2:]:
	opflags.append(arg)

print(opflags)

# Open the existing PCAP in a Reader
try:
	f = open(args[1], 'rb')
except:
	print("File not found, try full path or place pcapsrb.py & pcap in same path")
	exit()
pcap = dpkt.pcap.Reader(f)

# Open a Writer pointing to an output file
f_mod = open("{}_mod.pcap".format(args[1].split('.')[0]), 'wb')
pcap_mod = dpkt.pcap.Writer(f_mod)

print("Entering pcap", end='')

for timestamp, buf in pcap:

	# unpack into (mac src/dst, ethertype)
	eth = dpkt.ethernet.Ethernet(buf)
	
	# Replace MAC addresses if not flagged
	if("-pm" not in opflags and "--preserve-macs" not in opflags):
		eth.src = replace_mac(eth.src)
		eth.dst = replace_mac(eth.dst)

	# Replace IP addresses if not flagged
	if (isinstance(eth.data, dpkt.ip.IP) and eth.type == 2048):
		ip = eth.data
		if("-pi" not in opflags and "--preserve-ips" not in opflags):
			ip.src = replace_ip(ip.src)
			ip.dst = replace_ip(ip.dst) 

		# Walk into Layer >4 payload

		# TCP instance, preserve flags - possibly overwrite payload
		if (isinstance(ip.data, dpkt.tcp.TCP) and ip.p == 6):
			tcp = ip.data
			if ('-sp' in opflags or '--scrub-payload' in opflags):
				mask = ""
				for g in range(len(tcp.data)*2):
					i = random.randint(0,15)
					mask += f"{i:x}"
				tcp.data = bytes.fromhex(mask)

		# UDP instance, possibly overwrite payload
		elif (isinstance(ip.data, dpkt.udp.UDP) and ip.p == 17):
			udp = ip.data
			if ('-sp' in opflags or '--scrub-payload' in opflags):
				mask = ""
				for g in range(len(udp.data)*2):
					i = random.randint(0,15)
					mask += f"{i:x}"
				udp.data = bytes.fromhex(mask)

	# Replace IPv6 addresses if not flagged
	elif (isinstance(eth.data, dpkt.ip6.IP6) and eth.type == 34525):
		if("-pi" not in opflags and "--preserve-ips" not in opflags):
			ip6 = eth.data
			ip6.src = replace_ip6(ip6.src)
			ip6.dst = replace_ip6(ip6.dst)

		# TCP instance, preserve flags - possibly overwrite payload
		if (isinstance(ip6.data, dpkt.tcp.TCP) and ip6.p == 6):
			tcp = ip6.data
			if ('-sp' in opflags or '--scrub-payload' in opflags):
				mask = ""
				for g in range(len(tcp.data)*2):
					i = random.randint(0,15)
					mask += f"{i:x}"
				tcp.data = bytes.fromhex(mask)
				
		# UDP instance, possibly overwrite payload
		elif (isinstance(ip6.data, dpkt.udp.UDP) and ip6.p == 17):
			udp = ip6.data
			if ('-sp' in opflags or '--scrub-payload' in opflags):
				mask = ""
				for g in range(len(udp.data)*2):
					i = random.randint(0,15)
					mask += f"{i:x}"
				udp.data = bytes.fromhex(mask)

	# Replace ARP ethernet & ip address info
	elif (isinstance(eth.data, dpkt.arp.ARP) and eth.type == 2054):
		arp = eth.data
		if("-pm" not in opflags and "--preserve-macs" not in opflags):
			arp.sha = replace_mac(arp.sha)
			arp.tha = replace_mac(arp.tha)
		if("-pi" not in opflags and "--preserve-ips" not in opflags):
			if (len(arp.spa) == 16):
				arp.spa = replace_ip(arp.spa)
			else:
				arp.spa = replace_ip6(arp.spa)
			if (len(arp.tha) == 16):
				arp.tpa = replace_ip(arp.tpa)
			else:
				arp.tpa = replace_ip6(arp.tpa)

	else:
		print("Packet at timestamp: {} is non IP Packet type, therefore unsupported (as of right now)\ndata: {}".format(datetime.datetime.utcfromtimestamp(ts), eth.data.unpack()))

	# Write the modified (or unmodified, if not valid) packet
	pcap_mod.writepkt(eth, ts=timestamp)

	# each '.' means one packet read&written
	print(".", end='')

print()

f.close()
f_mod.close()