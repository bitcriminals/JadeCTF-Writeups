from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def Decrypt(ct, E, L):
    #L = R * E * R
    key = long_to_bytes(ZZ(sum(L.list())))[:32]
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    return unpad(pt, 32)

pub = eval(open("./rascal.txt").read())

n = pub['n']
M = MatrixSpace(Zmod(n), 2, 2)

P = M(pub['P'])
Q = M(pub['Q'])
G = M(pub['G'])
E = M(pub['E'])
ct = bytes.fromhex(pub['ct'])

MM = Q * G * ~Q
NN = P * G * ~P

a = G * NN -  MM * G
b = MM - NN

X = a * ~b
R_ = X[0][0] * M.identity_matrix() + G

X = Q * ~(R_ * P * R_)
u2 = X[0][0]
K = u2 * R_ * E * R_

print(Decrypt(ct, E, K))
