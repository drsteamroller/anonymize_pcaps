# Overview

`pcapsrb.py` is a script that utilizes the dpkt module to open and parse a pcap file, and then write the changes/scrub to a new pcap file. By default, it randomizes MAC and routable IPv4/6 addresses.

Every MAC/IP scramble will be consistent to the original value:

Example: All instances of IP address 8.8.8.8 will swapped to 67.32.118.253 [chosen randomly during runtime]

## Dependency

dpkt - https://github.com/kbandla/dpkt
```
pip install dpkt
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
-sp, --scrub-payload : Unintelligently* scrambles all data past TCP/UDP header info [*Not protocol-aware] 
```
