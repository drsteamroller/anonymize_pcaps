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
def replace_ip(ip):
	if (ip not in ip_repl.keys()):
		repl = ""
		for i in range(16):
			i = random.randint(0,15)
			repl += f'{i:x}'
		ip_repl[ip] = repl

		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip])

def replace_ip6(ip6):
	if (ip6 not in ip_repl.keys()):
		repl = ""
		for i in range(32):
			i = random.randint(0,15)
			repl += f'{i:x}'
		ip_repl[ip6] = repl

		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip6])

# Same philosophy, but with mac addresses
def replace_mac(mac):
	if (mac not in mac_repl.keys()):
		repl = ""
		for i in range(12):
			i = random.randint(0,15)
			repl += f'{i:x}'
		mac_repl[mac] = repl
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(mac_repl[mac])

options = {"--preserve-ips":"Program scrambles IP(v4&6) addresses by default, use this option to preserve original IP addresses","--preserve-macs":"Disable MAC address scramble","--scrub-payload":"Sanitize payload in packet (in development)"}

# Check if file is included
if (len(sys.argv) < 2):
	print("\nUsage:\n\tpcapsrb.py [file].pcap [options]\n\t--help -> for options\n")
	exit()

args = sys.argv

if (args[1] == "--help"):
	for k,v in options.items():
		print("\t{}: {}".format(k, v))
	exit()

else:
	if('.pcap' not in args[1]):
		print("Unsupported file format: \"{}\"\n", args[1])
		exit()

opflags = {"--preserve-ips": False, "--preserve-macs": False, "--scrub-payload": False}

for arg in args[2:]:
	if arg in opflags.keys():
		opflags[arg] = True
	else:
		print("Unrecognized option: {}".format(arg))
		exit()

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

#print(pcap.readpkts())

print("Entering pcap", end='')

for timestamp, buf in pcap:

	# unpack into (mac src/dst, ethertype)
	eth = dpkt.ethernet.Ethernet(buf)
	
	# Replace MAC addresses if not flagged
	if(not opflags["--preserve-macs"]):
		eth.src = replace_mac(eth.src)
		eth.dst = replace_mac(eth.dst)

	# Replace IP addresses if not flagged
	if (isinstance(eth.data, dpkt.ip.IP) and eth.type == 2048):
		if(not opflags["--preserve-ips"]):
			ip = eth.data
			ip.src = replace_ip(ip.src)
			ip.dst = replace_ip(ip.dst)

	# Replace IPv6 addresses if not flagged
	elif (isinstance(eth.data, dpkt.ip6.IP6) and eth.type == 34525):
		if(not opflags["--preserve-ips"]):
			ip6 = eth.data
			ip6.src = replace_ip6(ip6.src)
			ip6.dst = replace_ip6(ip6.dst)

	else:
		print("Packet at timestamp: {} is non IP Packet type, therefore unsupported (as of right now)\ndata: {}".format(datetime.datetime.utcfromtimestamp(ts), eth.data.unpack()))


	# Write the modified packet
	pcap_mod.writepkt(eth, ts=timestamp)

f.close()
f_mod.close()