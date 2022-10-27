First,we run psscan to see that thunderbird.exe is running.After that when we run filescan we can see  a corrupted picture in user directory of archi.Fix it to get part-1 of the flag.

Check inbox and sent files of thunderbird in system  with filescan and dumpfiles plugins of volatility to get a script and encrypted text.

Decrypt the text(2nd part)
```python
cipher = "5b2b7f05237305611f3368214d3a601d4325740f"#after decoding the b64 string

x = 0

decoded = ""

#function by harold

def gray2binary(x, s):

    shiftamount = s

    while x >> shiftamount:

        x ^= x >> shiftamount

        shiftamount <<= 1

    return x
for i in range(0, len(cipher) - 1, 2):
    a = int(cipher[i:i+2],16)
    if i > 0:
        x = int(cipher[i-2:i],16)
    l=a

    for s in range(1,5):

        l = gray2binary(l,s)

    l = l ^ x
    decoded += chr(l)
print(decoded)

```
After that we get a string encoded using ROT.Decode it to get the 2nd Part

Join the 2 parts to get the Final Flag.

**jctf{p34rl_1s_look1ng_f0r_Sandeep}
