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
-sp, --scrub-payload : Currently only aware of TFTP/DHCP, HTTP under construction
-ns : Non-standard ports used. By default pcapsrb.py assumes standard port usage, use this option if the pcap to be scrubbed uses non-standard ports.
        - To use -ns, you can supply an input file(-ns=<file>), or if you leave it blank, it will look for a file named "ports.txt" which is included in the GitHub
        - Additionally, you can utilize this option if you want to scrub certain protocols, but leave other protocols untouched. Set the ports (see ports.txt) you want to not scrub to -1 
```

## Map File

All FFI obfuscation programs (currently: pcapsrb, fortiobfuscator, and logscrub) output a map file containing mapped ipv4, ipv6, mac addresses, and strings (hostnames, usernames, etc). They exist to represent a human-readable mapping of the replacements made during the program's runtime.

One other use for these files is to be able to import them into each program to receive the same replacement for the same original value.

I.E ===>

logscrub.py is run, masking every instance of the value 10.0.0.1 to 10.0.14.102. The mapped values file is taken and imported for pcapsrb.py's run. pcapsrb.py will replace every instance 10.0.0.1 with 10.0.14.102, the same as logscrub.py

Currently, importing is being developed, but logscrub and FortiObfuscator have small implementations built in that provide this same functionality.

- FortiObfuscate.py allows for multiple configuration files to be read in, and it keeps the same value map during the runtime (as long as it is not quit out between loading configuration files)

- logscrub.py can take in multiple log files to perform the same replacements on the same original values