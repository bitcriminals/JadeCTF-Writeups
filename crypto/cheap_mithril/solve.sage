from Crypto.Util.number import long_to_bytes, inverse

exec(open("./data.txt").read())
e = 65537

F.<x> = PolynomialRing(Zmod(N))
FF = (e * x + A) ^ 2 - X
GG = (e * x + B) ^ 2 - Y

x_ = FF.monic().small_roots(X = 2^240, epsilon = 0.03)[0]
y_ = GG.monic().small_roots(X = 2^240, epsilon = 0.03)[0]

x_, y_ = ZZ(x_), ZZ(y_)
q = gcd(N, pow(A * pow(x_, x_, N), y_, N) - pow(B, x_, N))
q = ZZ(q)
p = N // ZZ(q)

assert p * q == N

flag = pow(ct, inverse(e, (p - 1) * (q - 1)), N)
print(long_to_bytes(ZZ(flag)))
