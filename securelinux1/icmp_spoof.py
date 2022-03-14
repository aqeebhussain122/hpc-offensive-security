import sys
from scapy.all import *

def usage():
    print("Usage: <Spoofed Source IP> <Target IP address>")
    return 1

def spoof_icmp(src_host, dst_host):
    ans,unans=sr(IP(src=src_host, dst=dst_host)/ICMP())

if len(sys.argv) != 3:
    usage()
else:
    spoof_icmp(sys.argv[1], sys.argv[2])
