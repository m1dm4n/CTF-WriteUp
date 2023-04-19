[![hackmd-github-sync-badge](https://hackmd.io/1rI_3sqkRLyupeJ4sX2ksA/badge)](https://hackmd.io/@m1dm4n/plaidctf2023)

# Predicting Math.random in node js and Crypto's write-ups for Plaid CTF 2023

## Summary

This is a serie of 4 challenges about predicting next random value of `Math.random()` in **node js**

According to answers for this [exchange](https://security.stackexchange.com/questions/84906/predicting-math-random-numbers), we know that **node js** use  [Xorshift128+ algorithm](https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L102) which is not cryptographically secure and should not be used for sensitive applications. I could easily found a script about using z3 smt solver to recover original state of given sequence outputs from `Math.random()` but it definitely not work for these chall. First we will go deeper for understanding the algorithm

#### How can Math.random() generates a random number between 0 and 1?

The algorithm has two state variables (**state0** and **state1**). Each iteration, **state1** is updated by a combination of XORs and shifts of the two state variables. **state0** gets the previous value of **state1**. Everything in the following Python code is ANDed with `MASK = 0xffffffffffffffff` in order to simulate 64 bit integers. Python code:

```python
def xs128p(state0, state1):
    s1 = state0
    s0 = state1
    s1 ^= (s1 << 23) & MASK
    s1 ^= (s1 >> 17) & MASK
    s1 ^= s0
    s1 ^= (s0 >> 26) & MASK
    return state1, s1
state0, state1 = xs128p(state0, state1)
```

In order to generate a random value between 0 and 1, 52 most significant bits of `state0` will be use for **fraction** bits of IEEE 754 double-precision format and `0x3fff` will be use for **Sign, Exponent** bits, this make `e = 1023` and `sign = 0`. The real value we will get is calculated by this fomula:

$$
-1^{sign}(1+\sum_{i=1}^{52}{2^{-i}}) * 2^{e-1023} = \
(1+\sum_{i=1}^{52}{2^{-i}})
$$

After subtract for 1, our output will always between 0 and 1.

```python
def to_double(value):
    double_bits = (value >> 12) | 0x3FF0000000000000
    return unpack('d', pack('<Q', double_bits))[0] - 1
state0, state1 = xs128p(state0, state1)
print(to_double(state0))
```

Also if you want convert the double value to 52 MSB bits of `state0`

```python
def from_double(dbl):
    return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF
```

But **v8** is cache 64 values in one time for faster performence and then generate output in reversed order so out `Math.random()` will be like this in python:

```python
def xs128p(state0, state1):
    s1 = state0
    s0 = state1
    s1 ^= (s1 << 23) & MASK
    s1 ^= (s1 >> 17) & MASK
    s1 ^= s0
    s1 ^= (s0 >> 26) & MASK
    return state1, s1
def to_double(value):
    double_bits = (value >> 12) | 0x3FF0000000000000
    return unpack('d', pack('<Q', double_bits))[0] - 1
def next_random(state0, state1):
    while True:
        cache = []
        for i in range(64):
            state0, state1 = xs128p(state0, state1)
            cache.append(to_double(state0))
        for i in reversed(cache):
            yield i
rng = next_random(..., ...)
print(next(rng))
```

#### Implementing symbolic PRNG state

Now that we had understanded the algorthm, we could see that new state are linear combinations of previous states.  We can model the states in 2 sets of 64 vectors over $\mathbf{GF}(2)$ (xor 2 bits work the same as adding 2 element in $\mathbf{GF}(2)$)

Define $V$ is an identity  matrix that contains 128 vectors, $S$ will be the result vector that contain 128 bits of `state` (we wil define `state` that contain 64 highest bits of `state0` and other is `state1` and $s_i$ will be i'th bit of `state` from left to right order), we will have $V * S = S$. For understanding why this method could symbolic the execution of Xorshift128+, i will take a example when we want to update `state0 = state0 ^ state1`.

It means that we take first 64 vectors of $V$ and add with last 64 vectors of $V$ in turn then multiple with $S$ and we will have new `state` like this:

$$
\begin{pmatrix}
    1_{1 - 1} & \dots & \dots & 1_{1 - 65}  & \dots  & 0_{1 - 128}  \\
    \vdots & \ddots &  & \vdots  & \ddots & \vdots \\
    \vdots &  & 1_{64 - 64} & \vdots &  &  1_{64 - 128}  \\
    0_{65 - 1} & \dotsb & \dots & 1_{65 - 65} & \dots  & 0_{65 - 128}  \\
    \vdots &  &  & \vdots  & \ddots & \vdots \\
    0_{128 - 1} & \dotsb & \dotsb & \dotsb & \dotsb   & 1_{128 - 128}
\end{pmatrix} * \
\begin{pmatrix}
s_1 \\ s_2 \\ \vdots \\ s_{64} \\ s_{65} \\ \vdots \\ s_{128}
\end{pmatrix} = \
\begin{pmatrix}
s_1 + s_{65} \\ s_2 + s_{66} \\ \vdots \\ s_{64} + s_{128} \\ s_{65} \\ \vdots \\ s_{128}
\end{pmatrix}
$$

Python code:

+ Implement `Add`(xor 2 states), `Shift left`. `Shift right` functions

```python
def Add(a, b):
    c = []
    for i, j in zip(a, b):
        c.append(i + j) #like i said, adding 2 vectors in GF(2) work same as xoring 2 numbers 
    return c
def SL(a, n):
    return a[n:] + [vector(F, 128)]*n
def SR(a, n):
    return [vector(F, 128)]*n + a[:64 - n]
```

+ Symbolic the `Xorshift128` function:

```python
def sym_xs128p(sym_state0, sym_state1):
    # Symbolically represent xs128p
    s1 = sym_state0
    s0 = sym_state1
    s1 = Add(s1, SL(s1, 23))
    s1 = Add(s1, SR(s1, 17))
    s1 = Add(s1, s0)
    s1 = Add(s1, SR(s0, 26))
    return sym_state1, s1
```

+ Since server have a limit time, i will store first 820 matrix of first 820 `Math.random()` output (as many as you need) for faster look up

```python
F = GF(2)
v = [vector(F, [0]*i + [1] + [0]*(127-i)) for i in range(128)]
state0 = v[:64]
state1 = v[64:]
N = 64 + (250+128)*2
Bigg = []
for i in range(N):
    state0, state1 = sym_xs128p(state0, state1)
    Bigg.append(state0[:-12]) # Output only using 52 bits for fraction
save(Bigg, f'equals')
```

As future states will be the sum of 64 subsets of our original 128 vectors, we could build a Coefficient matrix and solve a system of equations with 128 unknowns to recover original states after gathering enough outputs. Each output from `Math.random()` will give us 52 bits from current `state0`

#### Predicting next random value in challenge

First, i need to load previous symbolic matrixs

```python
equals = load(f'equals.sobj')
```

Remember that **node js** using cache each 64 numbers, so i create a function that work like a pivot in my equaltion lookups

```python
def next_idx():
    k = 63
    while True:
        for l in range(k, k-64, -1):
            yield l
        k += 64
```

Like i said above, we need to build a system of equations and solving it. Full rank matrix alway have a solution so we will feed the matrix until we have a matrix with rank 128

```python
def solve_random(payloads, pre_run, idx_rng, leaks, step=0):
    Ms = matrix(F, 128, 128)
    ans = vector(F, 128)
    c = 0
    for i in range(pre_run):
        next(idx_rng)
    for value in payloads:
        if c == 128:
            break
        i = next(idx_rng)
        for _ in range(step):
            next(idx_rng)
        for j in range(len(leaks[value])):
            if leaks[value][j] is None:
                continue
            Ms.set_row(c, equals[i][j])
            if Ms.rank() > c:
                ans[c] = leaks[value][j]
                c += 1
            if c == 128:
                break
    state = Ms.solve_right(ans)
    state0 = int(''.join(map(str, state[:64])), 2)
    state1 = int(''.join(map(str, state[64:])), 2)
    return state0, state1
```

Some explanation:

+ Note that `Math.random` might have been runned beforce leaking some output for us. That is why i have a param `pre_run` in above functions.

+ The output not alway leaks full random output for us, somthing like mulitplying with a number and then floor down to integer. It will just give a partial bits leak for us in some first MSB bits so we will need a `leaks` that return for us how many bits and value of it so we can adding the symbolic to our matrix

> for example with multiple is 4, 0 tell us first 2 bits is [0, 0], 1 is [0, 1], 2 is [1, 0], 3 is [1, 1]

+ `step` using for when each output call multiple time of `Math.random()`

[Testing the predicting](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/plaidCTF/fastrology/test)

```python
import os
import math
b4 = [
    [0, 0],
    [0, 1],
    [1, 0],
    [1, 1],
]
seed = os.urandom(16)
original_state0, orginal_state1 = int.from_bytes(
    seed[:8], 'big'), int.from_bytes(seed[8:], 'big')
print("original seed: (%s, %s)" % (original_state0, orginal_state1))
rng = next_random(original_state0, orginal_state1)

randoms = [next(rng) for i in range(15 + 192 + 128)]
mult = 4
payloads = [math.floor(random * mult) for random in randoms]
print("Last 128 value of payloads:\n\t", payloads[-128:])

state0, state1 = solve_random(payloads[15:-128], 15, next_idx(), b4)
print("recovered seed: (%s, %s)" % (state0, state1))

new_rng = next_random(state0, state1)
for i in range(15 + 192):
    next(new_rng)
predict_random = [math.floor(next(new_rng)*mult) for i in range(128)]
print("Predicted value:\n\t", predict_random)
```

![test_output](https://i.imgur.com/TFWHS3o.png)

We have just successfully predicted the `Math.random()`, so now we will go detail in each challenge.

## fastrology

[Repository](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/plaidCTF)

Server's source:

```python
import sys
import string
import random
import hashlib
import time
import subprocess

FLAGS = [
    '<real new moon flag is on the server>',
    '<real waxing crescent flag is on the server>',
    '<real waxing gibbous flag is on the server>',
    '<real full moon flag is on the server>'
]
NUM_TRIALS = 50
PHASES = ['new moon', 'waxing crescent', 'waxing gibbous', 'full moon']
PHASE_FILES = ['new_moon.js', 'waxing_crescent.js', 'waxing_gibbous.js', 'full_moon.js']
MAXTIMES = [15, 15, 15, 30]
USE_POW = False

if USE_POW:
    # proof of work
    prefix = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))
    print("Give me a string starting with {} of length {} so its sha256sum ends in ffffff.".format(prefix, len(prefix)+8), flush=True)
    l = input().strip()
    if len(l) != len(prefix)+8 or not l.startswith(prefix) or hashlib.sha256(l.encode('ascii')).hexdigest()[-6:] != "ffffff":
        print("Nope.", flush=True)
        sys.exit(1)

while True:
    phase = input(f'which phase? [{", ".join(PHASES)}]\n')
    if phase not in PHASES:
        continue
    phase = PHASES.index(phase)
    break

for trial in range(NUM_TRIALS):
    print(f'{PHASES[phase]}: trial {trial+1}/{NUM_TRIALS}', flush=True)
    tick = time.time()
    p = subprocess.run(['node', PHASE_FILES[phase]])
    tock = time.time()
    if abs(tock-tick) > MAXTIMES[phase]:
        print(f'⌛️❗️ ({tock-tick:.3f})', flush=True)
        sys.exit(1)
    if p.returncode != 42:
        print(f'🔮️🚫️❗️', flush=True)
        sys.exit(1)

print('congrats!', flush=True)
print(FLAGS[phase])
```

Out targets are all in node js file so the server don't have anything for us to focus. Just solving the Proof of Work and be careful with the time limit

### new moon

Source:

```node
const { randomInt, createHash } = require('node:crypto');
const readline = require('node:readline').createInterface({
  input: process.stdin,
  output: process.stdout,
});

const warmup_len = randomInt(64);
for (let i = 0; i < warmup_len; i++) {
    Math.random();
}

const prefix_len = 192;
const alphabet = '♈♉♊♋♌♍♎♏♐♑♒♓⛎';

let output = '';
for (let i = 0; i < prefix_len+128; i++) {
    output += alphabet[Math.floor(Math.random() * alphabet.length)];
}

const prefix = output.substring(0, prefix_len);
const expected = output.substring(prefix_len);

console.log(prefix);
console.log(createHash('md5').update(expected, 'utf8').digest('hex'));

readline.question('❓️\n', guess => {
    readline.close();
    if (guess === expected) {
        console.log('✅');
        process.exit(42);
    } else {
        console.log('❌');
        process.exit(1);
    }
});
```

After reading source code we know that server will call `Math.random` several times between 0 and 64, so we need brute force this offset or the matrix will go wrong.

Server give us 192 values after multiply `Math.random()` with 13 and then floor it down. Need to create a map for 13

```python
for i in range(13):
    print(f"{from_double(i/13):064b}"[12:])
```

```plain
0000000000000000000000000000000000000000000000000000
0001001110110001001110110001001110110001001110110001
0010011101100010011101100010011101100010011101100010
0011101100010011101100010011101100010011101100010100
0100111011000100111011000100111011000100111011000101
0110001001110110001001110110001001110110001001110110
0111011000100111011000100111011000100111011000101000
1000100111011000100111011000100111011000100111011000
1001110110001001110110001001110110001001110110001010
1011000100111011000100111011000100111011000100111011
1100010011101100010011101100010011101100010011101100
1101100010011101100010011101100010011101100010011110
1110110001001110110001001110110001001110110001001111
```

The map is what i call for an array that contain some leak bits correspond to its index. For example, when our value is 0, so it will might be between 0 and 1 => First 3 bits will always be 000. Continue doing this, we have this map 

```python
b13 = [
    [0, 0, 0],
    [0, 0],
    [0, 0, 1],
    [0],
    [0, 1],
    [0, 1, 1],
    [],
    [1, 0, 0],
    [1, 0],
    [1],
    [1, 1],
    [1, 1],
    [1, 1, 1]
]
```

Gathering all above information, we have this function:

```python
def solve_new_moon(payload, hash_check, alpha):
    known_idx = [alpha.index(i) for i in payload]
    mult = 13
    leaks = b13
    for pre_run in range(64):
        good = True
        state0, state1 = solve_random(
            known_idx, pre_run, next_idx(), leaks)
        rng = next_random(state0, state1)
        for j in range(pre_run):
            next(rng)
        for j in range(len(payload)):
            if floor(next(rng) * mult) != known_idx[j]:
                good = False
                break
        if not good:
            continue
        s = ""
        for j in range(128):
            s += alpha[floor(next(rng) * mult)]
        if md5(s.encode()).hexdigest() == hash_check:
            return s.encode()
    else:
        raise Exception("LMAO!!!!!!")
```

Output and flag:

![output1](https://i.imgur.com/YK30Hqk.png)

### waxing crescent

Source:

```node
const { randomInt, createHash } = require('node:crypto');
const readline = require('node:readline').createInterface({
  input: process.stdin,
  output: process.stdout,
});

const warmup_len = randomInt(64);
for (let i = 0; i < warmup_len; i++) {
    Math.random();
}

const prefix_len = 135;
const alphabet = '☊☋☌☍';

let output = '';
for (let i = 0; i < prefix_len+128; i++) {
    output += alphabet[Math.floor(Math.random() * alphabet.length)];
}

const prefix = output.substring(0, prefix_len);
const expected = output.substring(prefix_len);

console.log(prefix);
console.log(createHash('md5').update(expected, 'utf8').digest('hex'));

readline.question('❓️\n', guess => {
    readline.close();
    if (guess === expected) {
        console.log('✅');
        process.exit(42);
    } else {
        console.log('❌');
        process.exit(1);
    }
});
```

This challenge is the same as `new moon` challenge except using different alphabet with length 4 for multiple. For a number is a power of 2 (bit array is base 2 of a number) is easy for getting bits leak

```python
b4 = [
    [0, 0],
    [0, 1],
    [1, 0],
    [1, 1],
]
```

Using above solving function ans changing mutilple, mapping

```python
def solve_waxing_crescent(payload, hash_check, alpha):
    known_idx = [alpha.index(i) for i in payload]
    mult = 4
    leaks = b4
    for pre_run in range(64):
        good = True
        state0, state1 = solve_random(
            known_idx, pre_run, next_idx(), leaks)
        rng = next_random(state0, state1)
        for j in range(pre_run):
            next(rng)
        for j in range(len(payload)):
            if floor(next(rng) * mult) != known_idx[j]:
                good = False
                break
        if not good:
            continue
        s = ""
        for j in range(128):
            s += alpha[floor(next(rng) * mult)]
        if md5(s.encode()).hexdigest() == hash_check:
            return s.encode()
    else:
        raise Exception("LMAO!!!!!!")
```

Output and flag:

![output2](https://i.imgur.com/JbzKf92.png)

### full moon

Source:

```node
const { randomInt, createHash } = require('node:crypto');
const readline = require('node:readline').createInterface({
  input: process.stdin,
  output: process.stdout,
});

const warmup_len = randomInt(64);
for (let i = 0; i < warmup_len; i++) {
    Math.random();
}

const prefix_len = 600;
const alphabet = '☿♀♁♂♃♄♅♆♇';

let output = '';
for (let i = 0; i < prefix_len+128; i++) {
    let index = Math.floor(Math.random() * alphabet.length);
    let rand_max = Math.floor(Math.random() * 4);
    let distortion_len = Math.floor(i/125);
    for (let j = 0; j < distortion_len; j++) {
        index ^= Math.floor(Math.random() * rand_max);
    }
    index = Math.min(index, alphabet.length-1);
    output += alphabet[index];
}

const prefix = output.substring(0, prefix_len);
const expected = output.substring(prefix_len);

console.log(prefix);
console.log(createHash('md5').update(expected, 'utf8').digest('hex'));

readline.question('❓️\n', guess => {
    readline.close();
    if (guess === expected) {
        console.log('✅');
        process.exit(42);
    } else {
        console.log('❌');
        process.exit(1);
    }
});
```

There are now 9 characters in the alphabet but from index 125 will have some distortions added to the character sampling process. But after some local testing, i find that i don't need more over 128 outputs for matrix building so i didn't care about that.

Note that each character sampling always call at least 2 times `Math.random()` so additional `step` will be 1. Remember to add a function that simulate the sampling process and create a new leaks map for 9. Solve function:

```python
b9 = [
    [0, 0, 0],
    [0, 0],
    [0],
    [0, 1],
    [],
    [1, 0],
    [1],
    [1, 1],
    [1, 1, 1],
]
def solve_full_moon(payload, hash_check, alpha):
    mult = len(alpha)
    leaks = b9
    def full_moon(rng, i):
        idx = floor(next(rng) * mult)
        rand_max = floor(next(rng) * 4)
        distortion_len = floor(i/125)
        for _ in range(distortion_len):
            idx ^= floor(next(rng) * rand_max)
        return min(idx, mult-1)
    known_idx = [alpha.index(i) for i in payload]
    for pre_run in range(64):
        good = True
        ans = solve_random(
            known_idx, pre_run, next_idx(), leaks, 1)
        state0, state1 = ans
        rng = next_random(state0, state1)
        for j in range(pre_run):
            next(rng)
        for j in range(len(payload)):
            if full_moon(rng, j) != known_idx[j]:
                good = False
                break
        if not good:
            continue
        s = ""
        for j in range(len(payload), len(payload)+128):
            s += alpha[full_moon(rng, j)]
        if md5(s.encode()).hexdigest() == hash_check:
            return s.encode()
    else:
        raise Exception("LMAO!!!!!!")
```

Output and flag:

![output3](https://i.imgur.com/29zrGoM.png)

### waxing gibbous - Solved after contest end

Source:

```node
const { randomInt, createHash } = require('node:crypto');
const readline = require('node:readline').createInterface({
  input: process.stdin,
  output: process.stdout,
});

const warmup_len = randomInt(64);
for (let i = 0; i < warmup_len; i++) {
    Math.random();
}

const prefix_len = 250;
const alphabet = '♈♉♊♋♌♍♎♏♐♑♒♓⛎';

let backup = '';
for (let i = 0; i < prefix_len+128; i++) {
    let index = Math.floor(Math.random() * 12);
    backup += alphabet[index];
}

let output = '';
for (let i = 0; i < prefix_len+128; i++) {
    let index = Math.floor(Math.random() * alphabet.length);
    if (index === 12) {
        // OPHIUCHUS MUST BE CONCEALED
        output += backup[i];
    } else {
        output += alphabet[index];
    }
}

const prefix = output.substring(0, prefix_len);
const expected = output.substring(prefix_len);

console.log(prefix);
console.log(createHash('md5').update(expected, 'utf8').digest('hex'));

readline.question('❓️\n', guess => {
    readline.close();
    if (guess === expected) {
        console.log('✅');
        process.exit(42);
    } else {
        console.log('❌');
        process.exit(1);
    }
});

```

There are 13 characters like `new moon` but any instance of character at index 12 in alplabet will be replaced by some random backup characters that have been sampling before.

Therefore, we know that each output will have the following case:

+ Between `i` and `i+1`
+ Between 12 and 13

The leak mapping will be the `b13` like `new moon` with a strict case that bits might be between 12 and 13 (It's sad that my brain didn't think about it during contest :sneezing_face:). Since 12 is return `111` so just changing all bit 0 to `None` we have compatible mapping

```python
b_special = [
    [],
    [],
    [None, None, 1],
    [None],
    [None, 1],
    [None, 1, 1],
    [],
    [1],
    [1],
    [1],
    [1, 1],
    [1, 1],
    [1, 1, 1]
]
```

Increase the `pre_run` parameter to ignore the `backup` sampled string because we had added a strict case for bits leak when index is 12. Solve function:

```python
# solved after the contest ends
def solve_waxing_gibbous(payload, hash_check, alpha):
    known_idx = [alpha.index(i) for i in payload]
    mult = len(alpha)
    leaks = b_special
    prefix_length = 250
    for pre_run in range(64):
        good = True
        state0, state1 = solve_random(
            known_idx, pre_run + prefix_length + 128, next_idx(), leaks)
        rng = next_random(state0, state1)
        for j in range(pre_run):
            next(rng)
        backup = []
        for j in range(prefix_length + 128):
            backup.append(floor(next(rng) * 12))
        for j in range(250):
            idx = floor(next(rng) * mult)
            if idx == 12:
                idx = backup[j]
            if idx != known_idx[j]:
                good = False
                break
        if not good:
            continue
        s = ""
        for j in range(128):
            idx = floor(next(rng) * mult)
            if idx == 12:
                s += alpha[backup[prefix_length + j]]
            else:
                s += alpha[idx]
        if md5(s.encode()).hexdigest() == hash_check:
            return s.encode()
    else:
        raise Exception("LMAO!!!!!!")

```

Output and flag:

![output4](https://i.imgur.com/tT2S16H.png)


## bivalves

Source:

```python
from bitstream import BitStream
from bitstring import BitArray
import os

KEY = BitArray(os.urandom(10)).bin
IV = BitArray(os.urandom(10)).bin

print(IV)

state = BitArray(bin=(KEY + '0101000001010' + IV + '0'*4))
output_stream = BitStream()

def step(out=True):
    if out:
        output_stream.write(state[65] ^ state[92], bool)
    t1 = state[65] ^ state[92] ^ (state[90] & state[91]) ^ state[170]
    t2 = state[161] ^ state[176] ^ (state[174] & state[175]) ^ state[68]
    for i in range(92, 0, -1):
        state.set(state[i - 1], i)
    state.set(t2, 0)
    for i in range(176, 93, -1):
        state.set(state[i - 1], i)
    state.set(t1, 93)

for _ in range(708):
    step(False)

pt=BitArray(bytes=('''There once was a ship that put to sea
The name of the ship was the Billy O' Tea
The winds blew up, her bow dipped down
Oh blow, my bully boys, blow (huh)

Soon may the Wellerman come
To bring us sugar and tea and rum
One day, when the tonguing is done
We'll take our leave and go

She'd not been two weeks from shore
When down on her right a whale bore
The captain called all hands and swore
He'd take that whale in tow (huh)

Soon may the Wellerman come
To bring us sugar and tea and rum
One day, when the tonguing is done
We'll take our leave and go

- '''.encode('utf-8') + (open('flag.txt', 'rb').read())))

ciphertext = BitStream()
for i in range(len(pt)):
    step()
    ciphertext.write(output_stream.read(bool, 1)[0] ^ pt[i], bool)

print(ciphertext.read(bytes, len(pt) // 8))
```

This is a normal LFSR cipher but with mixing bits using `And` operator. You could read my friend's writeups  about it [link](https://github.com/sinkthemall/Cryptography_Writeup/tree/main/plaidCTF/2023). Here is my script [link](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/plaidCTF/bivalves)
