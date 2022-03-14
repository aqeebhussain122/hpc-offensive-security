#!/usr/bin/python3

import socket
import struct

message = "Hello world!"
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock_addr = socket.getaddrinfo("ff16::fe", 5000, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]

ttl = struct.pack('i', 5)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
sock.sendto(message.encode(), sock_addr)
print("Sending message to server")
