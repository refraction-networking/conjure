#!/usr/bin/python

import socket
import random
import struct
import sys

def rand_ips(prefix, n=1):
    net, plen = prefix.split('/')
    plen = int(plen)
    net_s = socket.inet_pton(socket.AF_INET6, net)
    net_n_hi, net_n_low = struct.unpack('!QQ', net_s)
    net_n = ((net_n_hi << 64) | net_n_low)
    mask = ((1<<plen)-1) << (128-plen)
    n_mask = ((1<<(128-plen))-1)
    for i in xrange(n):
        r = random.randint(0, 2**128)
        n = net_n | (r & n_mask)
        n_hi = n >> 64
        n_low = n & 0xffffffffffffffff
        s = struct.pack('!QQ', n_hi, n_low)
        yield socket.inet_ntop(socket.AF_INET6, s)



#for ip in rand_ips('2001:48a8::/32', int(sys.argv[1])):
for ip in rand_ips('2601::/20', int(sys.argv[1])):
    print ip


