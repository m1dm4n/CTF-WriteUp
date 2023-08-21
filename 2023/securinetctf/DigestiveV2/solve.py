from sage.all import *
from pwn import remote
from json import dumps, loads
from Crypto.Util.number import bytes_to_long,inverse
from CVP import CVP
import random

def pub_hash(m):
     return (bytes_to_long(m.encode())%O)>>60 

def solve(l, known, target, k=3):
    bound_choices = [(32, 63), (64, 95), (96, 127)]
    W = 2**192
    mat = matrix(ZZ, l + 2, l + 2)
    for i in range(l):
        mat[i, i] = 1
        mat[i, l + 1] = ((256**(i+20)) % O) * W
    mat[-2, -1] = ((known - target)) * W
    mat[-2, - 2] = W
    mat[-1, - 1] = O * W
    lhs = [32]*(l) + [W, 0]
    rhs = [127]*(l) + [W, 0]
    while True:
        idxs = random.choices(range(l), k=k)
        _l = lhs[:]
        _r = rhs[:]
        bss = random.choices(bound_choices, k=k)
        for idx, bs in zip(idxs, bss):
            _l[idx] = bs[0]
            _r[idx] = bs[1]
        result = CVP(mat, _l, _r, sanity_check=True)
        if not result:
            continue
        return bytes(result.list()[:l][::-1])

io = remote("crypto.securinets.tn", 8989)
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffc)
b = K(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1)
E = EllipticCurve(K, (a, b))
G = E(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)
E.set_order(0xffffffffffffffffffffffff99def836146bc9b1b4d22831 * 0x1)
O=6277101735386680763835789423176059013767194773182842284081
F = GF(O)
io.sendlineafter(b">2-admin verification\n\n", dumps({
    "option":"sign",
    "name":"A"*40
}).encode())
ret = loads(io.recvline(0))

# Get flag
l = 50
know = b'{"username": "' + b"\x00"*l + b'", "admin": "truee"}'
target = pub_hash(dumps({"username":"A"*40,"admin":"false"}))
print(target)
while True:
    name = solve(l, bytes_to_long(know), target << 60, 10).decode()
    payload = dumps({"username":name,"admin":"truee"})
    print(payload, pub_hash(payload))
    if pub_hash(payload) == target:
        break
io.sendline(dumps({
    "option":"verify_admin",
    "name":name,
    "r": ret['r'],
    "s": ret['s'],
}).encode())
io.interactive()
