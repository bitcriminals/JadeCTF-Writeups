from z3 import *
from lib51 import LFSR
from dataclasses import dataclass

@dataclass
class register:
    name: str
    val:  BitVec
    mid:  int
    mask: int
    taps: int
    out:  int

# changed logical operations to bitwise
def parity(r):
    r ^= r>>16
    r ^= r>>8
    r ^= r>>4
    r ^= r>>2
    r ^= r>>1
    return r & 1

def clockone(reg):
    t = reg.val & reg.taps
    reg.val <<= 1
    reg.val &= reg.mask
    reg.val |= parity(t)

def clockall():
    for reg in mem:
        clockone(reg)

def getbit():
    clockall()
    res = 0
    for reg in mem:
        res ^= parity(reg.val & reg.out)
    return res

r1 = register('r1', None, 0x000100, 0x07FFFF, 0x072000, 0x040000)
r2 = register('r2', None, 0x000400, 0x3FFFFF, 0x300000, 0x200000)
r3 = register('r3', None, 0x000400, 0x7FFFFF, 0x700080, 0x400000)

mem = [r1, r2, r3]

enc = bytes.fromhex(open("data.txt","r").read().split(' ')[-1])

for lp in range(0, len(enc) - 8):

    msg = enc[lp:]
    vecs = [BitVec(f'r{i}', 24) for i in range(1, 4)]
    for reg,vec in zip(mem, vecs):
        reg.val = vec

    pt = b"jadeCTF{"
    outs = ""
    for i,j in zip(msg, pt):
        outs += f"{i ^ j:08b}"

    s = Solver()
    for i in range(64):
        s.add(getbit() == int(outs[i]))

    if s.check() == sat:
        M = s.model()
        states = [M[i].as_long() for i in vecs]
    else:
        print("failed")
        continue

    strm = LFSR([0] * 8, 0)
    for i, reg in enumerate(strm.mem):
        reg.val = states[i]

    y = 0
    for i in range(len(msg) * 8):
        y <<= 1
        y |= strm.getbit()

    flag = bytes.fromhex(f"{int(msg.hex(), 16) ^ y :0x}")
    print(f"offset -> {lp}")
    print(f"flag -> {flag}")
