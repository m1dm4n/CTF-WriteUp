from struct import pack, unpack
from sage.all import GF, load, matrix, vector

F = GF(2)
equals = load(f'equals.sobj')
MASK = 0xFFFFFFFFFFFFFFFF

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
