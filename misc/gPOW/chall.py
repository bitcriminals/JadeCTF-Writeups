import numpy as np
import random
from secret import flag

# consts
xlim = 17
ylim = 9

def randomart(mat, inx):
    alphabet = b" .o+=*BOX@%&#/^ES"
    POW = bytearray([10])
    
    for i, row in enumerate(mat):
        POW += bytearray(alphabet[col] for col in row)
        
        if i == ylim//2:
            POW += f" = HASH(jade00{inx} - X)".encode()
        
        POW += b"\n"

    return POW[:-1].decode()

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
    
    return mat

flag = flag[8:-1].split("_")

print("Welcome Tester! Help us validate these PoWs by finding X")

for inx, word in enumerate(flag):
    secret = f"jade00{inx} - {word}".encode()
    POW = drunken_walk(secret)
    
    ART = randomart(POW, inx)
    print(ART)
    
    guess = input("> ")
    if guess != word:
        exit(0)

print("\nGG! Thank you for your services.")
