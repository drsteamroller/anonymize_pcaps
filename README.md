# Overview

`pcapsrb.py` is a script that utilizes the dpkt module to open and parse a pcap file, and then write the changes/scrub to a new pcap file. By default, it randomizes MAC and IPv4/6 addresses.

## Dependency

dpkt - https://github.com/kbandla/dpkt
`pip install dpkt`

## Usage

`python|python3 pcapsrb.py <pcap_file> <options>`

Options:
	`--help : Shows options`
	`--preserve-macs : Skips MAC address scramble`
	`--preserve-ips : Skips IP address scramble`
	`--scrub-payload : Unintelligently* scrambles all data past TCP/UDP ports [*Not protocol-aware]`