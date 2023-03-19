# Overview

`pcapsrb.py` is a script that utilizes the dpkt module to open and parse a pcap file, and then write the changes/scrub to a new pcap file. By default, it randomizes MAC and routable IPv4/6 addresses.

Every MAC/IP scramble will be consistent to the original value:

Example: All instances of IP address 8.8.8.8 will swapped to 67.32.118.253 [chosen randomly during runtime]

## Dependency

dpkt - https://github.com/kbandla/dpkt

ipaddress - https://github.com/python/cpython/blob/3.11/Lib/ipaddress.py 
```
pip install dpkt
pip install ipaddress
```

## Usage
```
python|python3 pcapsrb.py <pcap_file> <options>
```

Options:
```
--help : Shows options
-pm, --preserve-macs : Skips MAC address scramble
-pi, --preserve-ips : Skips IP address scramble
-sPIP, --scramble-priv-ips : Scramble RFC 1918 (private) IP addresses
-O=<OUTFILE> : Output file name for log file, which shows the ip/mac address mappings
-sp, --scrub-payload : Unintelligently* scrambles all data past TCP/UDP header info [*Not protocol-aware]
-ns : Non-standard ports used. By default pcapsrb.py assumes standard port usage, use this option if the pcap to be scrubbed uses non-standard ports.
        To use -ns, you can supply an input file(-ns=<file>), or if you leave it blank, it will look for a file named "ports.txt" which is included in the GitHub
```
