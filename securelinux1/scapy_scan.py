#! /usr/bin/python3
from scapy.all import *


def scan_port(dst_port):
    src_ip = "192.168.0.18"
    dst_ip = "192.168.0.85"
    src_port = RandShort()

    stealth_scan_resp = sr1(IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
    if(str(type(stealth_scan_resp)) == None):
        return "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
            print("{} is open".format(dst_port))
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            print("{} is closed".format(dst_port))
        elif(stealth_scan_resp.haslayer(ICMP)):
            if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                print("{} is filtered".format(dst_port))

scan_port(22)
scan_port(8080)
