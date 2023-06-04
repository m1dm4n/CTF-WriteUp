from pwn import remote, process
from sage.all import factor, randint, is_prime, GF, crt
from Crypto.Util.number import long_to_bytes, bytes_to_long
import libscrc
import os
io = remote('log.chall.ctf.blackpinker.com', 443, ssl=True)

B = 2 ** 50


def gen(p):
    while True:
        _p = randint(1, B)
        P = _p + (p << 50)
        ls = list(factor(P))
        if all(s.nbits() < 45 for s, _ in ls):
            return P, ls


def check(n, P, M, E):
    if P >> (82 - 4 * 8) == n:
        C = libscrc.darc82(M)
        if pow(bytes_to_long(M), E, P) == C % P:
            return True
    return False


n = int(io.recvline(0))
P, ps = gen(n)

while True:
    M = os.urandom(5)
    m = bytes_to_long(M)
    C = libscrc.darc82(M)
    rs = []
    ms = []
    try:
        for p, _ in ps:
            F = GF(p)
            _c = F(C)
            _m = F(m)
            assert _c.multiplicative_order() == _m.multiplicative_order()
            x = _c.log(_m)
            assert _m ** x == _c
            rs.append(x)
            ms.append(_m.multiplicative_order())
        E = crt(rs, ms)
    except Exception:
        continue
    if pow(bytes_to_long(M), E, P) == C % P:
        break

io.sendafter(b'=', str(P).encode())
io.sendafter(b'=', str(E).encode())
io.sendafter(b'=', M)


io.interactive()
