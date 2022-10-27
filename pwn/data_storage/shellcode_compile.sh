gcc -nostdlib -static "$1" -o shellcode
objcopy --dump-section .text=shellcode.bin shellcode
rm shellcode