#!/usr/bin/env python3
################################################################################
#                 PCAP sanitization for Federal customers
# Usage:
#		pcapsrb.py [file].pcap [options]
#		
# Options:
#		--help : Shows these options
#		-pm, --preserve-macs : Skips MAC address scramble
#		-pi, --preserve-ips : Skips IP address scramble
#		-sPIP, --scramble-priv-ips : Scramble RFC 1918 (private) IP addresses
#		-O=<OUTFILE> : Output file name for log file, which shows the ip/mac address mappings
#		-sp, --scrub-payload : Unintelligently* scrambles all data past TCP/UDP header info [*Not protocol-aware] 
#
# Author: Andrew McConnell
# Date:   03/09/2023
################################################################################


import sys
import dpkt
import random
import datetime
import ipaddress

# Global Variables
ip_repl = dict()
mac_repl = dict()
opflags = []
mapfilename = ""

# Helper functions

def isRFC1918(ip):
	hexd = ip.hex()
	if (hexd >= 'ac100000' and hexd <= 'ac20ffff'):
		return True
	elif (hexd >= 'c0a80000' and hexd <= 'c0a8ffff'):
		return True
	elif (hexd >= '0a000000' and hexd <= '0affffff'):
		return True
	else:
		return False
	
# Replaces IPs, but the same IP gets the same replacement
# >> I.E. 8.8.8.8 always replaces to (randomized) 144.32.109.200 in the pcap
# The point of these replacement commands is to make sure the same IP/MAC has the same replacement
def replace_ip(ip):
	# Account for broadcast/quad 0
	if (type(ip) is str):
		ip = bytes.fromhex(ip)
	if ((ip.hex()[-2:] == 'f'*2) or (ip.hex() == '0'*8)):
		return ip
	if(isRFC1918(ip) and ('-sPIP' not in opflags and '--scramble-priv-ips' not in opflags)):
		return ip			

	if (ip not in ip_repl.keys()):
		repl = ""
		if(isRFC1918(ip)):
			repl = ip.hex()[0:4]
			for h in range(4):
				i = random.randint(0,15)
				repl += f"{i:x}"
		else:
			for g in range(8):
				i = random.randint(0,15)

				# PREVENTS 0.X.X.X ADDRESSES
				while ((i + g) == 0):
					i = random.randint(0,15)

				repl += f'{i:x}'

		ip_repl[ip] = repl
		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip])

# Literally the same function as IPv4, except generates a longer address
def replace_ip6(ip6):
	# Account for broadcast/zero'd addresses
	if (ip6.hex() == 'f'*32 or ip.hex() == '0'*32):
		return ip6

	if (ip6 not in ip_repl.keys()):
		repl = ""
		for g in range(32):
			i = random.randint(0,15)
			repl += f'{i:x}'

			# PREVENTS 0:: ADDRESSES
			while ((i + g) == 0):
				i = random.randint(0,15)

		ip_repl[ip6] = str(repl)

		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip6])

# Same philosophy, but with mac addresses
def replace_mac(mac):
	# Account for broadcast/zero'd addresses
	if (mac.hex() == 'f'*12 or mac.hex() == '0'*12):
		return mac

	if (mac.hex() not in mac_repl.keys()):
		repl = ""
		for g in range(12):
			i = random.randint(0,15)
			repl += f'{i:x}'
		mac_repl[mac.hex()] = repl
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(mac_repl[mac.hex()])

# takes TCP/UDP packet data and determines/scrubs the data
def scrub_upper_prots(pkt):
	# UDP only protocols
	#	TFTP <
	# 	DHCP < dpkt does not like to recognize upper layer protocols. Currently finding solution

	# TCP only protocols
	# 	FTP
	# 	HTTP
	# 	SMTP
	# 	Telnet
	# 	IMAP/POP3

	# TCP/UDP
	# 	DNS
	return pkt

# Mappings file, takes the replacement dictionaries "ip_repl" and "mac_repl" and writes them to a file for easy mapping reference
def repl_dicts_to_logfile(filename):
	with open(filename, 'w') as outfile:
		outfile.write("+---------- MAPPED IP ADDRESSES ----------+\n")
		for og, rep in ip_repl.items():
			rep = int(rep, 16)
			if (len(og.hex()) <= 12):
				OGaddress = str(ipaddress.IPv4Address(og))
				SPaddress = str(ipaddress.IPv4Address(rep))
			else:
				OGaddress = str(ipaddress.IPv6Address(og))
				SPaddress = str(ipaddress.IPv6Address(rep))
			outfile.write(f"Original IP: {OGaddress}\nMapped IP: {SPaddress}\n\n")
		outfile.write("+---------- MAPPED MAC ADDRESSES ---------+\n")
		for og, rep in mac_repl.items():
			formatOG = ""
			for x in range(1, len(og), 2):
				formatOG += og[x-1] + og[x] + ':'
			formatREP = ""
			for y in range(1, len(rep), 2):
				formatREP += rep[y-1] + rep[y] + ':'
			formatOG = formatOG[:-1]
			formatREP = formatREP[:-1]
			outfile.write(f"Original MAC: {formatOG}\nMapped MAC: {formatREP}\n\n")
	print(f"Outfile written to: {filename}")

# Include private IP scramble
options = {"-pi, --preserve-ips":"Program scrambles routable IP(v4&6) addresses by default, use this option to preserve original IP addresses","-pm, --preserve-macs":"Disable MAC address scramble","-sPIP, --scramble-priv-ips":"Scramble private/non-routable IP addresses", "-O=<OUTFILE>":"Output file name for log file, which shows the ip/mac address mappings","-sp, --scrub-payload":"Sanitize payload in packet (Unintelligently)"}

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

for arg in args[2:]:
	if ("-O=" in arg):
		try:
			mapfilename = arg.split("=")
		except:
			print("-O option needs to be formatted like so:\n\t-O=<filename>")
		continue
	opflags.append(arg)

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

#############################################################################################
#								 Enter PCAP Scrubbing										#
#############################################################################################

print("Entering pcap", end='')

for timestamp, buf in pcap:

	# unpack into (mac src/dst, ethertype)
	eth = dpkt.ethernet.Ethernet(buf)
	
	# Replace MAC addresses if not flagged
	if("-pm" not in opflags and "--preserve-macs" not in opflags):
		eth.src = replace_mac(eth.src)
		eth.dst = replace_mac(eth.dst)

	# Replace IP addresses if not flagged
	if (isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6)):
		ip = eth.data
		if("-pi" not in opflags and "--preserve-ips" not in opflags):
			if (len(ip.src.hex()) == 8):
				ip.src = replace_ip(ip.src)
			else:
				ip.src = replace_ip6(ip.src)
			if (len(ip.dst.hex()) == 8):
				ip.dst = replace_ip(ip.dst)
			else:
				ip.dst = replace_ip6(ip.dst)

		# Check for ICMP/v6. Currently testing to see what needs to be masked
		if (isinstance(ip.data, dpkt.icmp.ICMP)):
			icmp = ip.data
			# print('ICMP data: %s' % (repr(icmp.data)))

		if (isinstance(ip.data, dpkt.icmp6.ICMP6)):
			icmp6 = ip.data
			# print('ICMP6 data: %s' % (repr(icmp6.data)))
			chk = icmp6.data
			icmp6cl = dpkt.icmp6.ICMP6
			if (isinstance(chk, icmp6cl.Error) or isinstance(chk, icmp6cl.Unreach) or isinstance(chk, icmp6cl.TimeExceed) or isinstance(chk, icmp6cl.ParamProb)):
				pass
			else:
				pass
				# Need to figure out how to access router advertisements, might be wise just to scrub the whole payload
				'''mask = ""
				for g in range(len(icmp6.data)*2):
					i = random.randint(0,15)
					mask += f"{i:x}"
				icmp6.data = bytes.fromhex(mask)'''

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
		if (isinstance(ip.data, dpkt.udp.UDP) and ip.p == 17):
			udp = ip.data

			udp.data = scrub_upper_prots(udp.data)
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
			# Replace source/destination mac in arp data body
			arp.sha = replace_mac(arp.sha)
			arp.tha = replace_mac(arp.tha)
		if("-pi" not in opflags and "--preserve-ips" not in opflags):
			if (len(arp.spa.hex()) <= 12):
				arp.spa = replace_ip(arp.spa)
			else:
				arp.spa = replace_ip6(arp.spa)
			if (len(arp.tha.hex()) <= 12):
				arp.tpa = replace_ip(arp.tpa)
			else:
				arp.tpa = replace_ip6(arp.tpa)

	else:
		print("Packet at timestamp: {} is of non IP Packet type, therefore unsupported (as of right now)\ndata: {}".format(datetime.datetime.utcfromtimestamp(ts), eth.data.unpack()))

	# Write the modified (or unmodified, if not valid) packet
	pcap_mod.writepkt(eth, ts=timestamp)

	# each '.' means one packet read&written
	print(".", end='')

print()

if (len(mapfilename) == 0):
	mapfilename = args[1].split('.')[0] + "_mpdaddr.txt"

repl_dicts_to_logfile(mapfilename)

f.close()
f_mod.close()