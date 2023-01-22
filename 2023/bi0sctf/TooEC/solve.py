from sage.all import *
from pwn import remote
from hashlib import md5
from Crypto.Util.number import long_to_bytes

N = 0xb4a8f1786f16b0ad10a2b5c4fdb020a192e963cf61eb3adb6eb55c41c41430a7313c158164b717516ae1f11e8f7b2df85b0d1843a519fd016894623384781eeed8e75f9bd38608d3fa734190ccde2b454e7de484b1600872b4fad839265656067b003c3f33c77345e8f55aa33234ac1b1e4d83d2f487ea1a042d4bdea3748bd3
a1 = 0x56fa7ac8a0c5710e0dce1057aa9a33d56a86c403a3a6c39bdd5a463744da4b5b3b29131e055661d2bf76b54793a27702981019f3f6664cc0cdcbe8da6fa1eeb
b1 = 0x7fc41ac9f450cc297109510e5bdab558d25b7e3bf8f8a8ef91bd0c9d985e5aa63f5364bc0bb3e4aa5f9c65780c6a7e633881daee64a1337f42a8c9d56c1ea3d1
a2 = 0x994df157f4e0aee044e654a2cbf8154d605c485268fe0ce660a28d3f474b88c598cc14b5bb199f39e97ea5dcedaad3540f472f690c7fb37895f405cb8a616b3
b2 = 0x18a94e4e31772e6893c73126196a91ebdee28b27289665b5ace04106e380d5618fce0003f543bb2f2dacf1ab249a8ed5bf990128b76664dfb9dc316ba1a31802

# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/coppersmith.py
import sys
import os
path = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)
from Helper.shared.partial_integer import PartialInteger
from Helper.crypto_attacks.factorization.coppersmith import factorize_p
p1 = "e078e75b3313660ec08eefcdfe98ca82ecea4f3483ce9055?????????05fa57d82f??????????525966d8eca5d968b96ca03e60f1b0a13cbd??????????ac39b"
p1 = PartialInteger.parse_be(p1, 16)
p1, p2 = factorize_p(N, p1, m=6, t=2)
print(f"{p1 = }")
print(f"{p2 = }")
# p1 = 11756567260683217973317821468013902925071857221209186747934466797087880003950030193785985576077722893781732403392136085606507535332326930255509329556456347
# p2 = 10790881175634558072269092254265802368362184550725174949593446030728701377842190431295222081606639424090650863572579036266274201231740288458629763480758313


E1 = EllipticCurve(GF(p1), [a1, b1])
G1 = E1.gens()[0]
q1 = G1.order()
E2 = EllipticCurve(GF(p2), [a2, b2])
G2 = E2.gens()[0]
q2 = G2.order()
print(f"{q1 = }")
print(f"{q2 = }")
# q1 = 11756567260683217973317821468013902925071857221209186747934466797087880003950056062657934676411779626195749253116443260159222430077031406604031496483294819
# q2 = 10790881175634558072269092254265802368362184550725174949593446030728701377842120947468767689818768068635638355158161266058040366019788593081905254490911663
io = remote("crypto.chall.bi0s.in", 10101)
def recover_priv(payload, n, BOUND):
    m = len(payload)
    mat = matrix(QQ, m + 2, m + 2)
    
    for i in range(m):
        z = int(md5(bytes([97+i])*50).hexdigest(), 16)
        r, s = payload[i]
        mat[i, i] = -n
        mat[m, i] = (r*inverse_mod(s, n)) % n
        mat[m + 1, i] = ((z*inverse_mod(s, n))) % n

    mat[m, m] = QQ(BOUND)/QQ(n)
    mat[m + 1, m + 1] = QQ(BOUND)

    for i in mat.LLL():
        if abs(i[-1]) == BOUND:
            return int(i[-2]*n/(BOUND))

payload1 = []
payload2 = []
for i in range(2):
    io.sendlineafter(b"Enter your choice: ", b"2")
    io.sendlineafter(b"Enter message to sign: ", bytes([97+i])*50)
    io.recvuntil(b"Curve 1: ")
    payload1.append(eval(io.recvline(0)))
    io.recvuntil(b"Curve 2: ")
    payload2.append(eval(io.recvline(0)))
io.close()
delta = 2**128
print(long_to_bytes(recover_priv(payload1, q1, delta)) +
      long_to_bytes(recover_priv(payload2, q2, delta)))
