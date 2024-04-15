from sage.all import *

m = 12
t = 172
F, z12 = GF(2**m).objgen()
R, x = PolynomialRing(F, 'x').objgen()
with open("output.txt", "r") as file_read:
    exec(file_read.readline().replace("^", "**"))
    S, x = R.quotient(f, 'x').objgen()
    exec(file_read.readline().replace("^", "**"))


def F2i(f):
	return int(''.join(map(str, list(f))), 2)


def decode(f, n=None):
    if n == None:
        return list(map(F2i, list(f)))
    return list(map(F2i, list(f)[:n]))


order = 0
_c = c

while True:
    _c = _c**2
    cs = decode(_c, 5)
    order += 1
    print(cs, order)
    if all(0 <= _ <= 255 for _ in cs):
        print(bytes(decode(_c)))
        break

# r = 39