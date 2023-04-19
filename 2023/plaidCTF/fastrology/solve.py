import re
import string
from hashlib import md5, sha256
from itertools import permutations
from math import floor
from struct import pack, unpack

import time
from mapping import *
from pwn import args, debug, info, log, process, remote
from sage.all import GF, load, matrix, vector

log.setLevel('DEBUG')
target = int(args.TARGET or 0)
F = GF(2)
equals = load(f'equals.sobj')
MASK = 0xFFFFFFFFFFFFFFFF
M = {4: b4, 13: b13, 9: b9}


def solve_pow(io):
    pow_re = re.compile(b"starting with (.*) of length 18")
    goal = b"\xff\xff\xff"
    prefix = pow_re.findall(io.recvline(0))[0]
    for s in permutations((string.ascii_letters + string.digits).encode(), 8):
        if sha256(prefix + bytes(s)).digest()[-3:] == goal:
            io.sendline(prefix + bytes(s))
            break


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


def next_idx():
    k = 63
    while True:
        for l in range(k, k-64, -1):
            yield l
        k += 64


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


def solve_new_moon_and_waxing_crescent(payload, hash_check, alpha):
    known_idx = [alpha.index(i) for i in payload]
    mult = len(alpha)
    leaks = M[mult]
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


def solve_waxing_gibbous(payload, hash_check, alpha):
    # solved after the contest ends
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


def solve_full_moon(payload, hash_check, alpha):
    mult = len(alpha)
    leaks = M[mult]

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


if args.LOCAL:
    io = process(['python3', 'server.py'])
else:
    io = remote("fastrology.chal.pwni.ng", 1337)
    solve_pow(io)
io.recvline()

alphas = ['♈♉♊♋♌♍♎♏♐♑♒♓⛎', '☊☋☌☍', '♈♉♊♋♌♍♎♏♐♑♒♓⛎', '☿♀♁♂♃♄♅♆♇']
PHASES = ['new moon', 'waxing crescent', 'waxing gibbous', 'full moon']
solve_funcs = [solve_new_moon_and_waxing_crescent,
               solve_new_moon_and_waxing_crescent, solve_waxing_gibbous, solve_full_moon]
io.sendline(PHASES[target].encode())
solve_func = solve_funcs[target]
alpha = alphas[target]


for i in range(50):
    io.recvline()
    debug(f"********* Trial {i+1:02}/50 *********")
    prefix = io.recvline(0).decode()
    hash_check = io.recvline(0).decode()
    debug(f"Prefix: " + prefix)
    debug(f"Result's Hash: " + hash_check)
    tick = time.time()
    ans = solve_func(prefix, hash_check, alpha)
    tock = time.time()
    # io.interactive()
    # break
    io.recvline()
    io.sendline(ans)
    io.recvline()
    if args.LOCAL:
        # Dont know why but testing on my Local need this line to work
        io.recvline()
    debug(f"******** end in {tock-tick:.04f} ********\n")

io.interactive()
