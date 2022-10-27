## Secure Terminal

This challenge involves using a hidden terminal in the [Rules page](https://jadectf.concetto.in/rules).<br />
To open the terminal, open the console in the rules page and run the `hello` function.

![image](https://user-images.githubusercontent.com/44190883/198251255-bf507153-071c-4433-aad3-0c328b2f6922.png)

Then, it's a simple Linux challenge. The flag is stored in the `.itshardtoseeme` file.

![image](https://user-images.githubusercontent.com/44190883/198251969-58458326-572f-4121-a776-58189cba0496.png)

## Discord

The flag is in the `About Me` section of the user `penguin#3505`'s profile
- they are the first to message in the crypto channel
- have a few memes in #memes

Some teams made use of the discord api, others bruteforced every user to get the flag!

Flag is, `jadeCTF{w3lc0m3_t0_0ur_d1sc0rd_s3rv3r}`

## gPOW

> based on [ssh key randomart](https://blog.benjojo.co.uk/post/ssh-randomart-how-does-it-work-art)

The challenge is simple enough once you identify the pattern.

```txt
$ nc 34.76.206.46 10012
Welcome Tester! Help us validate these PoWs by finding X

Bo=o+.o.o
+oE+ . +
 o    o
     o
      o S         = HASH(jade000 - X)
     . o
      o
     .

>
```

This ascii art is nothing but the randomart generated when generating a ssh-key or authorizing someone else's key.

```txt
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/masrt/.ssh/id_rsa): ./test
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in ./test.
Your public key has been saved in ./test.pub.
The key fingerprint is:
SHA256:i+7lcKH5v7slywfWnqDAG5ld1PsOWUHgfuInIb6d4Cg masrt@bitc-box
The key's randomart image is:
+---[RSA 2048]----+
|           ..o.  |
|          ... .  |
|         .  .. . |
|          ... .  |
|     . +S...++.  |
|      *+.++o++.  |
|      =++o++++.  |
|     .E*.+ B++.  |
|     .o.+.X=o    |
+----[SHA256]-----+
```

All that remains is understanding the algorithm and finding an input which generates the given randomart!

The dimensions for the art are 9 x 17, so the script first needs to parse that!

```python
alphabet = " .o+=*BOX@%&#/^ES"
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
```

While doing this, we can also estimate the number of characters that make up our POW. As every pair of bits, counts as one increment in the matrix.

For example, *jade000 - abc* would result in the matrix having a total sum of around 52!

Bruteforcing Time!

```python
import numpy as np
from string import ascii_lowercase

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

art, sz = recover_art()
prod = product(ascii_lowercase, repeat = sz)
poss = []
for x in prod:
    guess = ''.join(x)
    if drunken_walk(f"jade00{i} - {guess}".encode()) == art:
	    poss.append(guess)
```

We may get more than one string that generates a particular randomart, use the most appropriate sounding!

```txt
size -> 3
[*] soln -> ['ssh']
ssh
size -> 3
[*] soln -> ['has']
has
size -> 3
[*] soln -> ['art', 'drt', 'fpt']
art
size -> 3
[*] soln -> ['let']
let
size -> 4
[*] soln -> ['pass', 'pcqs']
pass
size -> 5
[*] soln -> ['wgkrt', 'wgnrq', 'wgzfq', 'worav', 'words']
words
size -> 4
[*] soln -> ['have']
have
size -> 4
[*] soln -> ['too!']
too!
```

Flag is, *jadeCTF{ssh_has_art_let_pass_words_have_too!}*
