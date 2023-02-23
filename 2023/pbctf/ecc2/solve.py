from sage.all import discrete_log
from sage.all import GF
from challenge import ECPoint
from hashlib import sha256
from pwn import remote, process
from sage.all import GF, PolynomialRing

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
BASE_POINT = (2, 2)
a = -3
b = 2
Gx, Gy = BASE_POINT


def gen(count, state):
    new_state = b''
    res = []
    last = 0
    for i in range(count - 1):
        hsh = sha256(state + i.to_bytes(1, 'big')).digest()[:10]
        new_state += hsh
        v = int.from_bytes(hsh, 'big')
        last ^= v
        res.append(v)

    hsh = last.to_bytes(10, 'big')
    new_state += hsh
    res.append(last)

    state = new_state
    key = sha256(state).digest()[:8]

    return res, key


def get_x(nonces: list[int]) -> bytes:
    ret = b""
    for nonce, mod in zip(nonces, MODS):
        p = ECPoint(BASE_POINT, mod)
        x = (nonce * p).x
        ret += x.to_bytes(13, "big")
    return ret


def dlog(F, a, b, Gx, Gy, Px, Py):
    """
    Solves the discrete logarithm problem on a singular curve (y^2 = x^3 + a2 * x^2 + a4 * x + a6).
    :param p: the prime of the curve base ring
    :param a2: the a2 parameter of the curve
    :param a4: the a4 parameter of the curve
    :param a6: the a6 parameter of the curve
    :param Gx: the base point x value
    :param Gy: the base point y value
    :param Px: the point multiplication result x value
    :param Py: the point multiplication result y value
    :return: l such that l * G == P
    """
    x = F["x"].gen()
    f = x ** 3 + a * x + b
    roots = f.roots()

    if roots[0][1] == 2:
        alpha = roots[0][0]
        beta = roots[1][0]
    elif roots[1][1] == 2:
        alpha = roots[1][0]
        beta = roots[0][0]
    else:
        raise ValueError("Expected root with multiplicity 2.")
    t = (alpha - beta).sqrt()
    u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha))
    v = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
    x = int(v.log(u))
    if x.bit_length() <= 80:
        return x
    v = (-Py + t * (Px - alpha)) / (-Py - t * (Px - alpha))
    x = int(v.log(u))
    return x


# io = remote("my-ecc-service-2.chal.perfect.blue", "1337")
io = process(["python", "challenge.py"])
io.sendlineafter(b'> ', b'G')
payload = bytes.fromhex(io.recvline(0).decode().split(': ')[-1])
io.sendlineafter(b'> ', b'V')
io.sendlineafter(b': ', (b'\x02\x02' + payload[2:]).hex().encode())
io.sendlineafter(b'> ', b'G')
payload = bytes.fromhex(io.recvline(0).decode().split(': ')[-1])

need = payload[10:]
Pxs = [int.from_bytes(need[i:i + 13], 'big') for i in range(0, len(need), 13)]
nonces = []
print('start')
for x, p in zip(Pxs, MODS):
    F = GF(p)
    Px = F(x)
    Py = F(Px**3 + a * Px + b).sqrt()
    nonce = dlog(F, a, b, Gx, Gy, Px, Py)
    print(nonce)
    nonces.append(nonce)
assert len(nonces) == len(MODS)
print('end')

state = b''.join(i.to_bytes(10, 'big') for i in nonces)
nonces, key = gen(len(MODS), state)
payload = payload[:2] + key + get_x(nonces)

io.sendlineafter(b'> ', b'P')
io.sendlineafter(b': ', payload.hex().encode())
print(io.recvline(0).decode())
