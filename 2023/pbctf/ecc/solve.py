from hashlib import sha256
from pwn import remote
from sage.all import EllipticCurve, GF, factor, discrete_log, crt
from Crypto.Util.number import inverse


class NonceGenerator:
    def __init__(self, inp):
        self.state = inp

    def gen(self):
        self.state = sha256(self.state + b'wow').digest()[:10]
        key = sha256(self.state).digest()[:8]

        return int.from_bytes(self.state, 'big'), key


class ECPoint:
    def __init__(self, point, mod):
        self.x = point[0]
        self.y = point[1]
        self.mod = mod

    def inf(self):
        return ECPoint((0, 0), self.mod)

    def _is_inf(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, other):
        assert self.mod == other.mod
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        assert self.mod == other.mod
        P, Q = self, other
        if P._is_inf() and Q._is_inf():
            return self.inf()
        elif P._is_inf():
            return Q
        elif Q._is_inf():
            return P

        if P == Q:
            lam = (3 * P.x**2 - 3) * inverse(2 * P.y, self.mod) % self.mod
        elif P.x == Q.x:
            return self.inf()
        else:
            lam = (Q.y - P.y) * inverse(Q.x - P.x, self.mod) % self.mod

        x = (lam**2 - P.x - Q.x) % self.mod
        y = (lam * (P.x - x) - P.y) % self.mod

        return ECPoint((x, y), self.mod)

    def __rmul__(self, other: int):
        base, ret = self, self.inf()
        while other > 0:
            if other & 1:
                ret = ret + base
            other >>= 1
            base = base + base
        return ret


def dlog(G, H, E):
    order = G.order()
    ms = []
    rs = []
    for i, j in factor(order):
        m = i**j
        _x = order//(m)
        _G = _x * G
        _H = _x * H
        r = discrete_log(_H, _G, operation='+')
        print(f"Found a log of order {m}: {r}")
        rs.append(r)
        ms.append(m)
    return crt(rs, ms)


def get_x(nonce: int) -> bytes:
    ret = b""
    for mod in MODS:
        p = ECPoint(BASE_POINT, mod)
        x = (nonce * p).x
        ret += x.to_bytes(13, "big")
    return ret


MODS = [
    942340315817634793955564145941,
    743407728032531787171577862237,
    738544131228408810877899501401,
    1259364878519558726929217176601,
    1008010020840510185943345843979,
    1091751292145929362278703826843,
    793740294757729426365912710779,
    1150777367270126864511515229247,
    763179896322263629934390422709,
    636578605918784948191113787037,
    1026431693628541431558922383259,
    1017462942498845298161486906117,
    734931478529974629373494426499,
    934230128883556339260430101091,
    960517171253207745834255748181,
    746815232752302425332893938923,
]
BASE_POINT = (2, 3)
a = -3
b = 7
assert 3**2 == (2**3 + a*2 + b)

# for p in MODS:
#     E = EllipticCurve(GF(p), [a, b])
#     G = E(2, 3)
#     print(factor(G.order()))
io = remote("my-ecc-service.chal.perfect.blue", 1337)
io.sendlineafter(b'> ', b'G')
payload = bytes.fromhex(io.recvline(0).decode().split(': ')[-1])
print(payload)

need = payload[10:]
xs = [int.from_bytes(need[i:i + 13], 'big') for i in range(0, len(need), 13)]


p = MODS[7]
F = GF(p)
E = EllipticCurve(F, [a, b])
H = E.lift_x(F(xs[7]))
nonce1 = int(dlog(E(BASE_POINT), H, E))
nonce2 = int(dlog(E(BASE_POINT), -H, E))

if nonce1.bit_length() < 80:
    nonce = nonce1
else:
    nonce = nonce2

nonce, key = NonceGenerator(nonce.to_bytes(10, 'big')).gen()
payload = b'\x02\x03' + key + get_x(nonce)

io.sendlineafter(b'> ', b'P')
io.sendlineafter(b': ', payload.hex().encode())
io.interactive()
