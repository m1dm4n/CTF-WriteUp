from sage.all import factor, GF, EllipticCurve, ZZ, crt, save, load, proof
from pwn import remote, process, args, log
from gmpy2 import isqrt

proof.all(False)
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
a = K(0x00)
b = K(0x04)
E = EllipticCurve(K, (a, b))
n = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
g1x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
g1y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
G1 = E(g1x, g1y)
order = n-1
Fn = GF(n)
# while True:
#     g = Fn.random_element()
#     if g.multiplicative_order() == n-1:
#         break
g = Fn(7)


def bsgs(base, g, H, sub):
    cnt = isqrt(sub) + 1
    c = ZZ((g ** cnt)**(-1))
    baby_steps = {}
    Hx = H.xy()[0]
    for i in range(cnt):
        key = (base * ZZ((g ** i))).xy()[0]
        if key == Hx:
            return i
        baby_steps[key] = i 
    y = H
    for j in range(cnt):
        tmp = baby_steps.get(y.xy()[0], None)
        if tmp is not None :
            return j*cnt + tmp
        y = c*y
    return None
def query(io, num):
    io.sendlineafter(b': ', str(num).encode())
    buffer = bytes.fromhex(io.recvline(0).decode())
    return int.from_bytes(bytes([buffer[0] & 0x1F]) + buffer[1:], 'big')
# def check_order(io):
#     factors = [(2, 32), (3, 1), (11, 1), (19, 1), (10177, 1), (125527, 1), (859267, 1), (906349, 2), (2508409, 1), (2529403, 1), (52437899, 1), (254760293, 2)]
#     real_order = n-1
#     for p, exp in factors:
#         for i in range(exp):
#             if query(io, real_order//p) != g1x:
#                 break
#             real_order //= p
#     return real_order*2

if args.LOCAL:
    io = process(['python', 'taas.py'])
else:
    io = remote('challs.actf.co', 32500)
# print(check_order(io))
if args.LOCAL:
    forder = 17478625058375396826482580169395321945896850833509212607534552899979527061504
    g = g ** (order//forder)
else:
    forder = 6554484396890773809930967563523245729711319062565954727825457337492322648064
    g = g ** (order//forder)
assert g ** forder == 1


ls = list(factor(forder))
# HS = []
# HS.append(E.lift_x(ZZ(query(io, forder//ls[0][0]**(ls[0][1])))))
# for i, (pi, ri) in enumerate(ls[1:]):
#     for j in range(ri):
#         HS.append(E.lift_x(ZZ(query(io, forder//pi**(j+1)))))
# save(HS, f'log_{1 if args.LOCAL else 2}')
io.close()
HS = iter(load(f'log_{1 if args.LOCAL else 2}'))
log.success("Successfully loading target points on Elliptic Curve!")

# Solving discrete log

## My baby step, giant step algorthm for subgroup 2 is fuck up so i will run through all 2**k
xs = [0]*len(ls)
xs[0] = bsgs(
    G1,
    g**(forder//ls[0][0]**(ls[0][1])),
    next(HS),
    ls[0][0]**(ls[0][1])
)
print(f"{ls[0][0]}**{ls[0][1]}: {xs[0]}")
for i, (pi, ri) in enumerate(ls[1:], start=1):
    print(f"{pi}**{ri}", end=': ')
    for j in range(ri):
        H = next(HS)
        mul = ZZ((g**(xs[i] * (forder//pi**(j+1))))**-1)
        c = bsgs(
            G1,
            g**(forder//pi),
            mul * H,
            pi
        )
        print(c, end=', ')
        xs[i] += c*(pi**j)
    print()
print(xs)

# xs = [240855109,
#       1,
#       8,
#       10,
#       9573,
#       70622,
#       790345,
#       255360342898,
#       91190,
#       442861,
#       26938561,
#       776799986542564]
modulus = [pi ** ri for pi, ri in ls]
ans = crt(xs, modulus)
print(int(-g**ans).to_bytes(32, 'big'))
print(int(g**ans).to_bytes(32, 'big'))