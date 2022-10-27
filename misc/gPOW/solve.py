from pwn import *
from math import ceil
import numpy as np
from string import ascii_lowercase
from itertools import product

# consts
xlim = 17
ylim = 9
alphabet = " .o+=*BOX@%&#/^ES"

def drunken_walk(secret):
    mat = np.zeros((ylim, xlim), int)
    x = xlim // 2
    y = ylim // 2
    for b in secret:
        for i in range(0, 8, 2):
            p = (b >> i) & 3
            if p & 1:
                if x < xlim - 1:
                    x += 1
            else:
                if x > 0:
                    x -= 1
            if p & 2:
                if y < ylim - 1:
                    y += 1
            else:
                if y > 0:
                    y -= 1

            mat[y][x] += 1
    mat[ylim // 2][xlim // 2] = -1
    mat[y][x] = -2
    
    return mat.tolist()

r = remote("34.76.206.46",10012) 
r.recvline()

def recover_art():
    r.recvline()
    data = r.recvuntil("> ")[:-3].decode().split("\n")
    data = [list(x)[:17] for x in data]
    
    count = 0
    for row in range(9):
        for col in range(17):
            data[row][col] = alphabet.index(data[row][col])
            if data[row][col] >= 15:
                data[row][col] -= 17
            count += abs(data[row][col])
    return data, round((count * 2) / 8) - 10


for i in range(8):
    art, sz = recover_art()
    prod = product(ascii_lowercase + "#?!_=+}{$@^&*", repeat = sz)
    
    print(f"size -> {sz}")
    poss = []
    for x in prod:
        guess = ''.join(x)
        if drunken_walk(f"jade00{i} - {guess}".encode()) == art:
            poss.append(guess)
    log.info(f'soln -> {poss}')
    r.sendline(input().strip())