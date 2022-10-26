## Cheap Mithril

This is your standard modular algebra problem mixed with coppersmith magic!
Seriously, this [wiki page](https://en.wikipedia.org/wiki/Coppersmith's_attack) is a treasure trove of knowledge.

 >cleaned up code
```python
flag = int.from_bytes(flag, "big")

nbits, rbits = 256, 240
e = 65537

while True:
    p = getPrime(nbits)
    q = getPrime(nbits)
    N = p * q
    tot = N + 1 - (p + q)
    if GCD(e, tot) == 1:
        d = inverse(e, tot)
        break

x = random.randint(0, 1<<rbits)
y = random.randint(0, 1<<rbits)

A = pow(p + q * y, x, N)
B = pow(q + p * x, y, N)

X = pow(e * x + A, 2, N)
Y = pow(e * y + B, 2, N)

ct = pow(flag, e, N)
assert pow(ct, d, N) == flag
```

At at glance:
- basic RSA public / priv key setup, with the 256 bit primes!
- two random variables - x, y around 240 bits
- four equations involving x, y, p & q

The key thing to note is, the bottom two equations for `X` & `Y`, can be solved independently since we have the values for `A` & `B`

$$
\begin{align}
X \equiv f(x) ^ 2  \bmod N \\
f(x) = e * x + A
\end{align}
$$

We need to find `x` (240 bits) and `N`  is (512 bits). If we knew the factorization of N, we could find f(x) using modular square root.

[*Coppersmith*](https://en.wikipedia.org/wiki/Coppersmith's_attack#Coppersmith_method) needs an appearance now.

The problem get reduced to finding a small root of f(x). Since `x` is around 240 bits and degree of the equation is 2, we can find an epsilon such that

$$
X = N ^ {1/d - \epsilon}
$$

so, 

$$\begin{align}
N ^ {240/512} \approx N ^ {1/2 - \epsilon} \\
\epsilon \approx 0.03125 
\end{align}
$$

Similary we find `y`.
```python
F.<x> = PolynomialRing(Zmod(N))
FF = (e * x + A) ^ 2 - X
GG = (e * x + B) ^ 2 - Y

x_ = FF.monic().small_roots(X = 2^240, epsilon = 0.03)[0]
y_ = GG.monic().small_roots(X = 2^240, epsilon = 0.03)[0]
```

Onto p,q now!
Both equations here are very similar, we can obtain either factor with some simple algebra

$$\begin{align}
& A = (p + q * y) ^ x \\
& B = (q + p * x) ^ y \\
& C = A * x ^ x = (p * x + q * x * y) ^ x \\
& C ^ y - B ^ x = (p * x + q * x * y) ^ {xy} - (p * x + q) ^ {xy} 
\end{align}
$$

We now have an equation of the form, 

$$ m ^ a - n ^ a$$

and such an equation always has 

$$ m - n $$

as one of its factors! Hence we get,

$$
(p * x + q * x * y - p * x - q) = q * (x * y - 1)
$$

And without any magic trick, we also have `q` as a factor of the equation. Taking the gcd with N should reveal q!

```python
x_, y_ = ZZ(x_), ZZ(y_)
q = gcd(N, pow(A * pow(x_, x_, N), y_, N) - pow(B, x_, N))
q = ZZ(q)
p = N // ZZ(q)

assert p * q == N
```

>solve.sage
```python
from Crypto.Util.number import long_to_bytes, inverse

N = 9554594442777956156176575410111600195877530714413341173170684511629274299512228887424722865581070074211220073375779601169613670191773041155190935992384503
A = 7461675696855485192498077806574979378047894821983865815839657530422849448689515297532903764658811059355302125460753210703381969189642182146350648776660800
B = 9434068242398921342211002064324465916062393376458086291548511274573416249033581548777010110839749584250133350250249137285226277646494093017384578041939028
X = 2307392417341885799596739085844264179388900683812340084993018869836755199903738815754854447496349782908851273354288563878127053152518798853361786098790086
Y = 8088051586635397321367808834017662405062741020871047546836555202710334915714609790269314128181137793132378471121286052630286539914489786777057686952350201
ct = 2820607551983845230812303368005639695109422590147246290345429705320752894016316200148900472636430606697622288535569496994810765077588892270595919635187359
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
print(long_to_bytes(ZZ(flag)).decode())
```

Flag is  `jadeCTF{mithril_is_peril_why_not_copper_with_gcd?}`

## Peepin' Over

>Based on [A5/1 cipher](https://en.wikipedia.org/wiki/A5/1)
>Implementation Reference - https://cryptome.org/jya/a51-pi.htm

The main security element of this steam cipher is its registers which are clocked irregularly. At every cycle atleast 2 of the 3 registers are clocked, using a majority rule based upon the middle bits of the registers.

![[1280px-A5-1_GSM_cipher.png]]

There has been ton of research that show recovering the state of the registers given a output stream, but none that runs in reasonable amount of time for a ctf. 
>The author spent a good 6-8 hrs looking for a working exploit but couldn't find one
> So he did the next most reasonable thing. Introduce a not so obvious bug.

```python
def parity(r):
    cn = 0
    while r:
        r &= (r - 1)
        cn += 1
    return cn & 1

class LFSR:
    def __init__(self, key, iv):
        self.r1 = register('r1', 0, 0x000100, 0x07FFFF, 0x072000, 0x040000)
        self.r2 = register('r2', 0, 0x000400, 0x3FFFFF, 0x300000, 0x200000)
        self.r3 = register('r3', 0, 0x000400, 0x7FFFFF, 0x700080, 0x400000)
        self.mem = (self.r1, self.r2, self.r3)
        self.setup(key, iv)
        
    def majority(self):
        res = 0
        for reg in self.mem:
            res += parity(reg.val & reg.mid)
        return res
    
    def clockone(self, reg):
        t = reg.val & reg.taps
        reg.val <<= 1
        reg.val &= reg.mask
        reg.val |= parity(t)
    
    def clockall(self):
        for reg in self.mem:
            self.clockone(reg)

    def clock(self):
        maj = self.majority()
        for reg in self.mem:
            if (reg.val & reg.mid != 0) <= maj:
                self.clockone(reg)
    
    def getbit(self):
        self.clock()
        res = 0
        for reg in self.mem:
            res ^= parity(reg.val & reg.out)
        return res
    
    def setup(self, key, iv = 0):
        for i in range(64):
            self.clockall()
            kbit = (key[i >> 3] >> (i & 7)) & 1
            for reg in self.mem:
                reg.val ^= kbit

        for i in range(22):
            self.clockall()
            fbit = (iv >> i) & 1
            for reg in self.mem:
                reg.val ^= fbit

        for i in range(100):
            self.clock()
```

B - ugs
- the *majority* function should return `res > 1`, instead returns only `res`
- the check condition in the *clock* function should be
```python
if (reg.val & reg.mid != 0) == maj:
```

This results in all the registers getting clocked at every cycle!

Solution? Our problem has been drastically simplified and now we can use z3 to solve for the internal state of the registers given we know some part of the plaintext!

***jadeCTF{***  - duh!

>64 bits are enough to recover the state (not proven)

>recover_state.py
```python
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

r1 = register('r1', BitVec('r1', 24), 0x000100, 0x07FFFF, 0x072000, 0x040000)
r2 = register('r2', BitVec('r2', 24), 0x000400, 0x3FFFFF, 0x300000, 0x200000)
r3 = register('r3', BitVec('r3', 24), 0x000400, 0x7FFFFF, 0x700080, 0x400000)

mem = [r1, r2, r3]

ct = REDACTED
pt = b"jadeCTF{"
strm = ""
for i,j in zip(ct, pt):
    strm += f"{i ^ j:08b}"
    
s = Solver()
for i in range(64):
    s.add(getbit() == int(strm[i]))

if s.check() == sat:
    M = s.model()
	states = [M[i].as_long() for i in vecs]
	print(states)
else:
	print("failed")
```

the script above recovers the state using z3! To get the plaintext back, reinstantiate a new LFSR and manually set the registers to these recovered states. The bitstream produces in the output should xor with the ciphertext to give the flag!

> The prompt stated that the flag was not in the beginning of the encrypted string

Thus we need to loop over all the positions. (flag starts at offset *92*)

Flag is `jadeCTF{a5/1__is_good_enough_as_long_as__its_clocked_correctly}`

## Inverse or Not

>Based on [Cayley-Purser Algorithm](https://en.wikipedia.org/wiki/Cayley%E2%80%93Purser_algorithm)

>Another Nice Source - https://mathworld.wolfram.com/Cayley-PurserAlgorithm.html

>Ref for Version without Inverses - https://eprint.iacr.org/2018/270.pdf

The algorithm is simple enough, we have two matrices from $GL_2(Z_n)$. They are used to generate some public key elements and one of the matrices is kept private.

The attack perspective comes from the 2x2 nature of the scheme. As per Cayley-Hamilton Theorem every square matrix A over a commutative ring, satisfies its own characteristic polynomial, $det(A - x * I_n)$
If n=2, the polynomial is quadratic and its turn out that any power of A can be expressed as a linear combination of $A$ and $I_2$

>challenge was Minecraft themed, but has no relation to the game

```python
# allay.sage

def encrypt(pt, P, Q, G, n):
	...

def decrypt(ct, E, R):
	...

r = random.randint(0, n)
G = R ^ r
Q = ~R * ~P * R  # ~ means inverse
pt = REDACTED

ct, E = encrypt(pt, P, Q, G, n)

# given are n, P, Q, G, E, ct
# public key is (n, P, Q, G)
# private key is (R, p, q)
```

ultimate goal is to recover a multiple of R, and we can do that using only the public key info

$$\begin{align}
\alpha = \frac{P^{-1} * G - G * Q}{Q - P^{-1}} \\
R' = \alpha * I_2 + G
\end{align}
$$

We can now use R' instead of R in the decrypt function and get the flag!

>solve_allay.sage
```python
# attack using public info
def decrypt(ct, E, R):
    L = ~R * E * R
    pt = L * ct * L
    return pt

pub = eval(open("../build/glare.txt").read())

n = pub['n']
M = MatrixSpace(Zmod(n), 2, 2)

P  = M(pub['P'])
Q  = M(pub['Q'])
G  = M(pub['G'])
E  = M(pub['E'])
ct = M(pub['ct'])

a = ~P * G - G * Q
b = Q - ~P

X = a * ~b
H = X[0][0] * M.identity_matrix() + G

pt = decrypt(ct, E, H)
print(pt)
```

You get, `jadeCTF{c4yl3y_purs3r`

For the second part, we have a variation by Slavin

```python
# snigger.sage

def Encrypt(pt, P, Q, G, n):
    ...

def Decrypt(ct, E, R):
	L = R * E * R
    ...

r = random.randint(0, n)
G = R ^ r
Q = R * P * R

pt = REDACTED
ct, E = Encrypt(pt, P, Q, G, n)

# given are n, P, Q, G, E, ct
# public key is (n, P, Q, G)
# private key is (R, p, q)
```

If you read the paper, this variant can also broken using only the public information and we can easily find a multiple of R

$$\begin{align}
M = Q * G * Q^{-1} \\
N = P * G * P^{-1} \\
\alpha = \frac{G * N - M * G}{M - N} \\
R' = \alpha * I_2 + G
\end{align}
$$

Although unlike the previous algorithm, obtaining R' is not enough. Since there are no inverses involved in the decryption, we wont find the correct value of the key *L*

However we can find exact value of L using a different way. Consider the equations,

$$\begin{align}
	Q = R * P * R \\
	L = R * E * R
\end{align}
$$

We have the value of R', so we can say $R = \mu * R'$.

Hence, $Q = \mu^2 * R' * P * R'$ and $L = \mu ^ 2 * R' * E * R'$.
We can easily solve for $\mu^2$ from the first equation and use it to find L. Thus making this variant broken as well.

>solve_sniffer.sage
```python
def Decrypt(ct, E, L):
    #L = R * E * R
    key = long_to_bytes(ZZ(sum(L.list())))[:32]
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    return unpad(pt, 32)

pub = eval(open("../build/rascal.txt").read())

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
```

You get, `_4lgor1thm_fl4wed_4FF}`

Flag is `jadeCTF{c4yl3y_purs3r_4lgor1thm_fl4wed_4FF}`

## Ep 3.9

Typical Cipher challenge, this one was the *german* variant of the Beaufort cipher (which means it could also be solved using Vigenere Techniques)

The enciphering key was `CASSIANANDOR` which resulted in

```txt
> echo("A planet killer! That's what he called it.")  
> delete("When has become now, Director Krennic.", y)  
> execute("This town is ready to blow.", x)  
> y = "The reactor module, that's the key. That's the place I've laid my trap."  
> y.append("Save the Rebellion! Save the dream!")  
> xor("The Force moves darkly near a creature that is about to kill.", "Luke")  
> Darth Vader - execute("Be careful not to choke on your aspirations, Director.")  
> echo("Rebellions are built on hope.")  
> send("Rogue One, pulling away.")  
> x = name_of_the_track(Qemb3iBlp1o)  
> x = x.lower().replace(" ", "_")  
> print(f"jadeCTF{x}")
```

Everything is *Star Wars Fanboying* except the last 3 lines! 

`x` is apparently the name of some track, `Qemb3iBlp1o`

Searching for `Qemb3iBlp1o` on Google, results in a Youtube Video Titled
`Your Father Would Be Proud (From "Rogue One: A Star Wars Story"/Audio Only)`

Flag is `jadeCTF{your_father_would_be_proud}`
