
## But why

To "stack pivot" just means to move the stack pointer elsewhere. It's a useful ROP technique and applies in cases where your initial chain is limited in size (as it is here) or you've been able to write a ROP chain elsewhere in memory (a heap spray perhaps) and need to 'pivot' onto that new chain because you don't control the stack.
## There's more

In this challenge you'll also need to apply what you've previously learned about the .plt and .got.plt sections of ELF binaries. If you haven't already read Appendix A in the beginners' guide, this would be a good time. This challenge imports a function named foothold_function() from a library that also contains a ret2win() function.
## Offset

The ret2win() function in the libpivot shared object isn't imported, but that doesn't mean you can't call it using ROP! You'll need to find the .got.plt entry of foothold_function() and add the offset of ret2win() to it to resolve its actual address. Notice that foothold_function() isn't called during normal program flow, you'll have to call it first to update its .got.plt entry.
## Count the ways

There are a few different ways you could approach this problem; printing functions like puts() can be used to leak values from the binary, after which execution could be redirected to the start of main() for example, where you're able to send a fresh ROP chain that contains an address calculated from the leak. Another solution could be to modify a .got.plt entry in-place using a write gadget, then calling the function whose entry you modified. You could also read a .got.plt entry into a register, modify it in-memory, then redirect execution to the address in that register.

Once you've solved this challenge by calling ret2win(), you can try applying the same principle to the libc shared object. Use one of the many pointers to libc code in the binary to resolve libc (there are more than just the .got.plt entries), then call system() with a pointer to your command string as its 1st argument, or a one-gagdet. You can also go back and use this technique against challenges like "callme".
