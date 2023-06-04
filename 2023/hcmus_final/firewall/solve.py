from libscrc import ecma182
from pwn import remote
from sage.all import *

PR, x = PolynomialRing(GF(2), 'x').objgen()
g = x**64 + x**62 + x**57 + x**55 + x**54 + x**53 + x**52 + x**47 + x**46 + x**45 + x**40 + x**39 + x**38 + x**37 + x**35 + x**33 + \
    x**32 + x**31 + x**29 + x**27 + x**24 + x**23 + x**22 + x**21 + \
    x**19 + x**17 + x**13 + x**12 + x**10 + x**9 + x**7 + x**4 + x + 1
n = g.degree()


def i2p(F, x):
    return F(Integer(x).bits())


def p2i(p):
    return Integer(p.list(), 2)


def crc(data, init, g, n=64):
    F = g.parent()
    x = F.gen()
    k = len(data) * 8
    W = i2p(F, int.from_bytes(data, "big"))
    I = i2p(F, init)
    value = (W * x**n + I * x**k) % g
    return p2i(value)


def crc_forgery_append(init, desired, g, n=64):
    """
    find data which satysfies crc(data, init) == desired
    the bit length of data is n
    """
    F = g.parent()
    x = F.gen()
    D = i2p(F, desired)

    I = i2p(F, init)

    xninv = inverse_mod(x**n, g)
    W = ((D - I * x**n)*xninv) % g
    return int(p2i(W)).to_bytes((n + 7) // 8, 'big')


target = b"Exit"
prefix = b"Flag"
init = crc(prefix, 0, g)
postfix = crc_forgery_append(init, ecma182(target), g)
assert ecma182(prefix + postfix) == ecma182(target)
payload = prefix + postfix


io = remote("firewall.chall.ctf.blackpinker.com", int(443), ssl=True)
io.recvline()
io.send(payload)
io.interactive()
