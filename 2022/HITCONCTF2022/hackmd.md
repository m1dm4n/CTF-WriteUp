# HITCON CTF 2022

## BabySSS - Crypto - 94 solves
### Description
> I implemented a toy Shamir's Secret Sharing for fun. Can you help me check is there any issues with this?
> 
> Author: maple3142

[Attachments](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2022/HITCONCTF2022/babysss/babysss-1068a45edf321eee75c9ceb3241a9941ab8bdc07.tar.gz)
### Solution
First look at the source file:
```python=
from random import SystemRandom
from Crypto.Cipher import AES
from hashlib import sha256
from secret import flag

rand = SystemRandom()


def polyeval(poly, x):
    return sum([a * x**i for i, a in enumerate(poly)])


DEGREE = 128
SHARES_FOR_YOU = 8  # I am really stingy :)

poly = [rand.getrandbits(64) for _ in range(DEGREE + 1)]
shares = []
for _ in range(SHARES_FOR_YOU):
    x = rand.getrandbits(16)
    y = polyeval(poly, x)
    shares.append((x, y))
print(shares)

secret = polyeval(poly, 0x48763)
key = sha256(str(secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR)
print(cipher.encrypt(flag))
print(cipher.nonce)
```
We can see that it's a Shamir’s Secret Sharing but in on Integer field ($\mathbb{ZZ}$). The challenge give us 8 shares and ask us to recover all 129 coefficients of poly.

Each shares give to us have a form like this:
$$
(x_i, y_i) = (x_i, a_{129}x_i^{128} + a_{128}x_i^{127}+...+a_{2}x_i + a_{1})
$$

So basically for each share $i$ if you get $y_i \% x_i$, you will get $a_1\%x_i$ . With 8 shares you could use **CRT** (Chinese Remainder Theorem) to recover a1 and then subtract that a1, divide $x_i$ and countinue to do that until you have all 129 coefficients

All coefficients in poly are 64-bit integers and all shared *$x_i$ are 16-bit integer but we have 8 shares so it's enough for us to recover each coefficients.

- [Script](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2022/HITCONCTF2022/babysss/solve.py)
- Output:
```python
b'hitcon{doing_SSS_in_integers_is_not_good_:(}'
```


## Secret - Crypto - 41 solves
### Description
> Too many secrets ...
> 
> Author: lyc

[Attachments](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2022/HITCONCTF2022/secret/secret-e35f5c21e032b74b1ab8110722c593847c2534cb.zip)

### Solution

My basic idea is from this latest [N1CTF](https://tl2cents.github.io/2022/11/08/N1CTF-2022-Crypto-Writeups-By-tl2cents/). We will use lattice to recover the modulus $p$ then recover the modulus $N$ and decrypt flag.

#### Recover modulus p

Why we need recover $p$ first?

Well you can in see the source code that the public key is $p + e_i$ and we don't know $p$ but we know all $e_i$. So if we get $c_i$ (i'th ciphertext) modulo with $p$, we will get $c_i\equiv m^{p+e_i}\equiv m^{e_i + 1}\pmod{p}$.

All $e_i$ are 512-bit integer so it's too big for us to apply direct power so we will construce a lattice to narrow down the exponents. The lattice is as follows:
$$
M = \begin{bmatrix}
e_1 & 1 & 0 &... & 0 \\
e_2 & 0 & 1 &... & 0 \\
\vdots & \vdots & \vdots& \ddots & \vdots \\
e_{64} & 0 & 0 &... & 1 \\
\end{bmatrix} 
$$
And than apply the LLL algorithm to $M will give you all small linear combinations (list $k_i$) of all rows in $M$. Define $ML=M.LLL()$ and $ML_i$ will be the i'th row of $ML$, $ML_i$ will have the form $[r_i, k_{i1}, k_{i2}, \ldots, k_{i64} ]$ such that:
$$
r_i = \sum\limits_{j=1}^{64} e_j*k_{ij}
$$

And the most important that $k_i$ is small so we can apply the power direct to $c_i$. Since we don't have $m_i$, we can't apply the exponent $r_i$. But we was given 64 $c_i$ and $e_i$ so we can find a pair $r_i$ and $r_j$ such that
$$
\begin{equation}
k_1*r_i = k_2*r_j 
\iff m^{k_1*r_i} = m^{k_2*r_j}
\iff m^{k_1*r_i} - m^{k_2*r_j} = K*p = 0 \pmod{p} 
\end{equation}
$$
And $m^{r_{i}}$ can simple calculate since we have linear combination of list $e_i$:
$$
\begin{align}
e_1*k_{i1} + e_2*k_{i2} + \cdots + e_{64}*k_{i64} &= r_i\\
\iff m^{e_1*k_{i1} + e_2*k_{i2} + \cdots + e_{64}*k_{i64}} &= m^{r_i} \\
\end{align}
$$
Note: since $k_{ij}$ can be negative or positive, we should seperate the list $k_i$ into 2 list: `pos` and `neg`. The equaltion will like this:
$$
m^{r_i} = \
\begin{cases}
\frac{m^{epos_1*pos_{i1} + epos_2*pos_{i2} + \cdots + epos_{64}*pos_{i64}}}{m^{eneg_1*neg_{i1} + eneg_2*neg_{i2} + \cdots + eneg_{64}*neg_{i64}}} \ \text{if }r_i > 0 \\
\frac{m^{eneg_1*neg_{i1} + eneg_2*neg_{i2} + \cdots + eneg_{64}*neg_{i64}}}{m^{epos_1*pos_{i1} + epos_2*pos_{i2} + \cdots + epos_{64}*pos_{i64}}} \ \text{if }r_i < 0
\end{cases}
$$

So if we get enough $K_i*p$, we could get **GCD** the list of it and get the modulus $p$ 

Code:
```python=
def solve(ess, bit_need):
    L = len(ess)
    M1 = matrix.identity(ZZ, L)
    mates = matrix(ZZ, L, 1)
    for i, e in enumerate(ess):
        mates[i, 0] = e
    mat = block_matrix(ZZ, [mates, M1], ncols=2)
    mat = mat.LLL()
    # for row in mat:
    #     logging.info(row)
    ns = []
    for row1, row2 in combinations(list(mat.rows()), 2):
        a, b = abs(row1[0]), abs(row2[0])
        k1, k2 = 1, 1
        if a % b == 0:
            k2 *= a // b
        elif b % a == 0:
            k1 *= b // a
        else:
            continue
        try:
            logging.info(f"Found a good pair: a = {row1[0]}, b = {row2[0]}")
            k1 = compute(row1)**k1
            k2 = compute(row2)**k2
            ns.append(mpz((k1 - k2).numerator()))
        except ValueError:
            continue
        if len(ns) > 2:
            p = gcd(*ns)
            logging.debug(f"Found a gcd with {p.bit_length()} bits")
            if p.bit_length() <= bit_need:
                return p
    return p
new_es = []
for e in es:
    new_es.append(e + 1)
p = solve(new_es, 1024)
logging.debug(f"Found p: {p}")
```
```python
[INFO]: Found a good pair: a = 84, b = 42
[INFO]: Found a good pair: a = -224, b = 112
[INFO]: Found a good pair: a = -224, b = 56
[DEBUG]: Found a gcd with 29601 bits
[INFO]: Found a good pair: a = -24, b = -120
[DEBUG]: Found a gcd with 1024 bits
[DEBUG]: Found p: 114123489471785231935784934808971699969409921187241213856052699152350022529522625133249122600992294384493330729753558097354310956450782137388609095123051712848950720360020186805006589596948820312938610934162552701552428320073591829720623902109809701883779673050594202312941073709061911680769616320309646800153
```

#### Recover modulus N

Since we have $p$, we just need change the argument for the `solve` function to list of $p + e_i$ and number of bits that we need will be $2048$
```python=
new_es = []
for e in es:
    new_es.append(e + p)
n = solve(new_es, 2048)
logging.debug(f"Found n: {n}")
```
```python
[INFO]: Found a good pair: a = 292, b = 4
[INFO]: Found a good pair: a = 66, b = 11
[INFO]: Found a good pair: a = 66, b = 198
[DEBUG]: Found a gcd with 542856 bits
[INFO]: Found a good pair: a = 66, b = -330
[DEBUG]: Found a gcd with 408759 bits
[INFO]: Found a good pair: a = 52, b = -156
[DEBUG]: Found a gcd with 34762 bits
[INFO]: Found a good pair: a = 52, b = -104
[DEBUG]: Found a gcd with 34762 bits
[INFO]: Found a good pair: a = 52, b = 4
[DEBUG]: Found a gcd with 34762 bits
[INFO]: Found a good pair: a = 52, b = 260
[DEBUG]: Found a gcd with 2048 bits
[DEBUG]: Found n: 17724789252315807248927730667204930958297858773674832260928199237060866435185638955096592748220649030149566091217826522043129307162493793671996812004000118081710563332939308211259089195461643467445875873771237895923913260591027067630542357457387530104697423520079182068902045528622287770023563712446893601808377717276767453135950949329740598173138072819431625017048326434046147044619183254356138909174424066275565264916713884294982101291708384255124605118760943142140108951391604922691454403740373626767491041574402086547023530218679378259419245611411249759537391050751834703499864363713578006540759995141466969230839
```

#### Decrypting flag
We have $N$ and $p$ so we just find $e$ in the list $es$ such that $\mathbb{GCD}(p+e, (p-1)*(q-1))=1$ and then using basic RSA decryption to get flag
```python=
q = n//p
phi = (p-1)*(q-1)
for e in es:
    if gcd(p+e, phi) != 1:
        continue
    d = inverse(p+e, phi)
    logging.debug("FLAG: hitcon{" + long_to_bytes(
        pow(cs[es.index(e)], d, n)).split(b'hitcon{')[-1].decode().strip())
    break
```
```python
[DEBUG]: FLAG: hitcon{K33p_ev3rythIn9_1nd3p3ndent!}
```

[Script](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2022/HITCONCTF2022/secret/solve.sage)

## RCE - Web - 157 solves

> Hello, I am a Random Code Executor, I can execute r4Nd�M JavaScript code for you ><
> 
> Tips:
> Have you ever heard of Infinite monkey theorem? If you click the "RCE!" button enough times you can get the flag 😉
> 
> Author: splitline

[Attachment](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2022/HITCONCTF2022/rce/rce-4bc5d3c73ac0fd8c0b098e9e7ac5a2e1c7a2fcf6.zip)

### Solution
app.js:
```javascript=
const express = require('express');
const cookieParser = require('cookie-parser')
const crypto = require('crypto');

const randomHex = () => '0123456789abcdef'[~~(Math.random() * 16)];

const app = express();
app.use(cookieParser(crypto.randomBytes(20).toString('hex')));

app.get('/', function (_, res) {
    res.cookie('code', '', { signed: true })
        .sendFile(__dirname + '/index.html');
});

app.get('/random', function (req, res) {
    let result = null;
    if (req.signedCookies.code.length >= 40) {
        const code = Buffer.from(req.signedCookies.code, 'hex').toString();
        try {
            result = eval(code);
        } catch {
            result = '(execution error)';
        }
        res.cookie('code', '', { signed: true })
            .send({ progress: req.signedCookies.code.length, result: `Executing '${code}', result = ${result}` });
    } else {
        res.cookie('code', req.signedCookies.code + randomHex(), { signed: true })
            .send({ progress: req.signedCookies.code.length, result });
    }
});

app.listen(5000);
```
The souce code is short so it just have 2 funtions: home page and random page

The home page `/` just have a button and when we click it, the server will send a GET requests to the `/random`

The random fuction will check if the length of `code` in the cookie is greater of equal 40 so it will `unhex` and `eval` the code and return `result` to us else it will random a hex char and append it to `code` in cookie

We can't manipulate the cookie because the signature but we could make the server sign a cookie we need. Just repeatly send a cookie until the next random character is a char we want.

The payload need small than 40 (20 since it's in hex format) so normal payload won't work here. My solution is using nest  evaluation(`eval(eval(somthing_here))`). Since all the code you eval will directly impact to server so from here have many way to exploit:
+ You could asign the code to a variable and then request again (but you will need a lot cookie)
+ Using `req.query.abcd` (`abcd` to fit the target length or anything you like). Only need 1 cookie and then request server with `/random?abcd={code_excute}` 
+ ...

And send the code to read the flag on the server with your signed cookie.

[Script](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2022/HITCONCTF2022/rce/solve.py)