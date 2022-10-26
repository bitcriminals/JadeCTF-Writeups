# attack using public info
def decrypt(ct, E, R):
    L = ~R * E * R
    pt = L * ct * L
    return pt

pub = eval(open("./glare.txt").read())

n = pub['n']
M = MatrixSpace(Zmod(n), 2, 2)

P  = M(pub['P'])
Q  = M(pub['Q'])
G  = M(pub['G'])
E  = M(pub['E'])
ct = M(pub['ct'])

a = P.inverse() * G - G * Q
b = Q - P.inverse()

X = a * b.inverse()
H = X[0][0] * M.identity_matrix() + G

pt = decrypt(ct, E, H).list()
flag = b"".join([bytes.fromhex(f"{ZZ(x):0x}") for x in pt])
print(flag.decode())
