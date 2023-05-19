from pwn import remote, success, process
from json import loads, dumps
from hashlib import sha256
from itertools import product
import re
import string
import random
io = remote('sigiso.challs.m0lecon.it', int(8888))
# io = process(['sage', 'server.sage'])
ls = list(prime_range(3, 117))
p = 4 * prod(ls) - 1
F = GF(p)
base = 0
N = len(ls)
T = 30
B = 5

R.< t > = GF(p)[]
def montgomery_coefficient(E):
    a, b = E.short_weierstrass_model().a_invariants()[-2:]
    r, = (t**3 + a*t + b).roots(multiplicities=False)
    s = sqrt(3*r**2 + a)
    return -3 * (-1)**is_square(s) * r / s
def csidh(pub, priv):
    E = EllipticCurve(F, [0, int(pub), 0, 1, 0])
    for es in ([max(0, +e) for e in priv], [max(0, -e) for e in priv]):
        while any(es):
            P = E.random_element()
            k = prod(l for l, e in zip(ls, es) if e)
            P *= (p+1) // k
            for i, (l, e) in enumerate(zip(ls, es)):
                if not e:
                    continue
                k //= l
                Q = k*P
                if Q == 0:
                    continue
                phi = E.isogeny(Q)
                E, P = phi.codomain(), phi(P)
                es[i] -= 1
        E = E.quadratic_twist()
    return int(montgomery_coefficient(E))
def sub(a, b):
    return [x-y for x, y in zip(a, b)]


def sign(msg, sk):
    fs = []
    Es = []
    for i in range(T):
        f = [random.randint(-B, B) for _ in range(N)]
        E = csidh(base, f)
        fs.append(f)
        Es.append(E)
    s = ",".join(map(str, Es)) + "," + msg
    h = int.from_bytes(sha256(s.encode()).digest(), "big")
    outs = []
    for i in range(T):
        b = (h >> i) & 1
        if b:
            outs.append(
                {"bit": int(b), "vec": [int(x) for x in sub(fs[i], sk)]})
        else:
            outs.append({"bit": int(b), "vec": [int(x) for x in fs[i]]})
    return outs
def solve_pow(io):
    pow_re = re.compile(b"starting in (.*) such that its sha256sum ends in (.*)\.")
    prefix, goal = pow_re.findall(io.recvline(0))[0]
    goal = goal.decode()
    for s in product((string.ascii_letters + string.digits).encode(), repeat=6):
        if sha256(prefix + bytes(s)).hexdigest()[-len(goal):] == goal:
            io.sendline(prefix + bytes(s))
            success("PoW done!")
            break
solve_pow(io)
# print(io.recvline())

pub = int(io.recvline(0).split(b': ')[-1])

def Choose(n: int):
    io.sendlineafter(b"> ", str(n).encode())

def get_sign():
    Choose(1)
    io.sendlineafter(b"?\n", b"lmao")
    res = loads(io.recvline(0))
    return res['signature']

C = [set() for i in range(N)]

while True:
    pays = get_sign()
    for pay in pays:
        bit = pay['bit']
        if bit == 0:
            continue
        vec = pay['vec']
        for i, j in enumerate(vec):
            C[i].add(j)
    print([max(c) - min(c) for c in C])
    if all(max(c) - min(c) >= 10 for c in C):
        break    
priv = [int(5 - max(c)) for c in C]
assert csidh(base, priv) == pub

# Forge signature and get flag
msg = "gimmetheflag"
sig = sign(msg, priv)
Choose(2)
io.sendlineafter(b"\n", dumps({"msg": msg, "signature": sig}).encode())
io.interactive()