from math import ceil, sqrt

from gmpy2 import powmod, invert, isqrt

def bsgs(g, h, p, sub):
    n = isqrt(sub) + 1
    # Baby Step
    baby_steps = {powmod(g, i, p): i for i in range(n)}
    # Giant Step
    c = invert(powmod(g, n, p), p)
    y = h
    for j in range(n):
        if y in baby_steps:
            return j*n + baby_steps[y]
        y = (y * c) % p
    return None

def calculate(base, g, x, sub, p):
    return powmod(base, powmod(g, x, sub), p)


def a_bsgs(base, g, h, sub, order, p):
    n = isqrt(sub) + 1
    baby_steps = {powmod(base, powmod(g, i, order), p): i for i in range(n)}
    c = invert(powmod(g, n, order), order)
    y = h
    for j in range(n):
        if y in baby_steps:
            return j*n + baby_steps[y]
        y = powmod(y, c, p)
    return None


base = 11288527919165059848519515166273414831840315594853904968290837711858807212808039779  # generator
# 16-bit prime number
p = 33228299483226416149683156473594397435549476976269360922357002896198879265138781023

g = 7
x = 13123123123123122222222222222222222222222222222222222222222222223423234  # secret exponent
n = 52435875175126190479447740508185965837690552500527637822603658699938581184513
order = n -1
sus = powmod(g, x, n)
print(sus)
h = powmod(base, sus, p)  # public key
# h = pow(g, x, n)
print(h)

ls = [(2, 32), (3, 1), (11, 1), (19, 1), (10177, 1), (125527, 1), (859267, 1), (906349, 2), (2508409, 1), (2529403, 1), (52437899, 1), (254760293, 2)]

modulus = [pi ** ri for pi, ri in ls]
l = [0]*len(ls)

for i, (pi, ri) in enumerate(ls):
    for j in range(ri):
        c = a_bsgs(
            base,
            powmod(g, order//pi, n),
            powmod(
                powmod(base, powmod(sus, order//pi**(j+1), n), p), 
                invert(powmod(g, l[i] * (order//pi**(j+1)), n), n),
                p
            ),
            pi,
            n,
            p
        )
        l[i] += c*(pi**j)
from sage.all import crt
print(l)
ans = int(crt(l, modulus))

print(pow(g, ans, n))
