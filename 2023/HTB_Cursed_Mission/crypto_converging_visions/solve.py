from sage.all import ZZ
from sage.all import Qp
from sage.all import EllipticCurve
from pwn import remote, process
from sage.all import GF, gcd, EllipticCurve
import random
from functools import reduce

# Lifts a point to the p-adic numbers.


class PRNG:

    def __init__(self, p, mul1, mul2, seed):
        self.mod = p
        self.exp = 2
        self.mul1 = mul1
        self.mul2 = mul2
        self.inc = int.from_bytes(b'Coordinates lost in space', 'big')
        self.seed = seed

    def rotate(self):
        self.seed = (self.mul1 * pow(self.seed, 3) + self.mul2 * self.seed +
                     self.inc) % self.mod
        return self.seed, pow(self.seed, self.exp, self.mod)


def _lift(E, P, gf):
    x, y = map(ZZ, P.xy())
    for point_ in E.lift_x(x, all=True):
        _, y_ = map(gf, point_.xy())
        if y == y_:
            return point_


def smart_attack(G, P):
    """
    Solves the discrete logarithm problem using Smart's attack.
    More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"
    :param G: the base point
    :param P: the point multiplication result
    :return: l such that l * G == P
    """
    E = G.curve()
    gf = E.base_ring()
    p = gf.order()
    assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    E = EllipticCurve(
        Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in E.a_invariants()])
    G = p * _lift(E, G, gf)
    P = p * _lift(E, P, gf)
    Gx, Gy = G.xy()
    Px, Py = P.xy()
    return int(gf((Px / Py) / (Gx / Gy)))


def setup(x=None):
    if x == None:
        x = random.getrandbits(255)
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'x: ', str(x).encode())
    line = io.recvline(0)
    if line == b'Point not on curve':
        return False
    return eval(line)


def get_payload():
    io.sendlineafter(b'> ', b'2')
    # print(io.recvline())
    io.recvline()
    _, x, y = eval(io.recvline(0))
    return (x, y)


# def recover_mod(P1, P2, P3):
#     # https://hackmd.io/@mystiz/uiuctf-2020-nookcrypt gives a nice explicit formula
#     x1, y1 = P1
#     x2, y2 = P2
#     x3, y3 = P3
#     return (y1 ** 2 - y2 ** 2 - x1 ** 3 + x2 ** 3) * (x2 - x3) - (
#         y2 ** 2 - y3 ** 2 - x2 ** 3 + x3 ** 3
#     ) * (x1 - x2)


# def recover_ab(p, x1, y1, x2, y2):
#     a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
#     b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
#     return int(a), int(b)


# io = remote("104.248.169.175", 32500)
# while True:
#     line = setup()
#     if line:
#         break
# _, Px, Py = line
# # io.interactive()
# payloads = [get_payload() for i in range(12)]

# p = int(reduce(gcd, [recover_mod(*ps)
#            for ps in zip(payloads[:10], payloads[1:11], payloads[2:12])]))
# a, b = recover_ab(p, payloads[0][0], payloads[0][1], payloads[1][0], payloads[1][1])
# print(f"{p = }")
# print(f"{a = }")
# print(f"{b = }")
# io.close()

io = remote("165.232.108.249", 32507)

p = 91720173941422125335466921700213991383508377854521057423162397714341988797837
a = 57186237363769678415558546920636910250184560730836527033755705455333464722170
b = 47572366756434660406002599832623767973471965640106574131304711893212728437629
F = GF(p)
E = EllipticCurve(F, [a, b])
_, Gx, Gy = setup(int(E.gens()[0].xy()[0]))
P = E(Gx, Gy)
EP = E(Gx, Gy)

_EP = E(get_payload())
seed = int(F(smart_attack(EP, _EP)).sqrt())
assert (seed**2) * EP == _EP

P = seed * P
seed, enc = PRNG(p, a, b, seed).rotate()
Ex, Ey = (seed * P).xy()

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b'x: ', str(Ex).encode())
io.sendlineafter(b'y: ', str(Ey).encode())
io.interactive()
