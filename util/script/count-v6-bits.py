#!/usr/bin/python

import sys
import socket

for line in sys.stdin.readlines():
    try:
        n = int(socket.inet_pton(socket.AF_INET6, line.strip()).encode('hex'), 16)
    except:
        continue
    count = bin(n)[2:].count('1')
    #print line.strip(), count
    print count

