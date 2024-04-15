from sage.all import *

m = 12
t = 172
F, z12 = GF(2**m).objgen()
R, x = PolynomialRing(F, 'x').objgen()
with open("test.txt", "r") as file_read:
    exec(file_read.readline())
    S, x = R.quotient(f, 'x').objgen()
    exec(file_read.readline())


def F2i(f):
	return f.to_integer()


def decode(f, n=None):
    if n == None:
        return list(map(F2i, list(f)))
    return list(map(F2i, list(f)[:n]))


_c = c
order = 0
while True:
    _c = _c**2
    cs = decode(_c, 5)
    print(cs, order)
    order += 1
    if all(0 <= _ <= 255 for _ in cs):
        msg = decode(_c)
        print(msg)
        print(bytes(msg))
        break