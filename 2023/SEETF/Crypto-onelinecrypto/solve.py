from sage.all import *
from itertools import product
from Crypto.Util.number import bytes_to_long
from CVP import CVP
import re
import random


def check(flag: str):
    return re.fullmatch(r'SEE{\w{23}}', flag)


MOD = 13 ** 37
m = 23
W = 2**256
flag = bytearray(b'SEE{' + bytes(m) + b'}')
mat = matrix(ZZ, m + 2, m + 2)
for i in range(m):
    mat[i, i] = 1
    mat[i, m + 1] = (((2**(8*(i + 1)))) % MOD) * W
mat[-2, -1] = (bytes_to_long(flag) % MOD) * W
mat[-2, - 2] = W
mat[-1, - 1] = MOD * W
for v in mat:
    print(*['1' if j == 1 else '*' if j else '.' for j in v], sep=' ')


l = [48]*(m) + [W, 0]
r = [122]*(m) + [W, 0]

L = 6
bound_choices = [(48, 58), (65, 90), (95, 122)]
while True:
    idxs = random.sample(range(23), k=L)
    _l = l[:]
    _r = r[:]
    for bs in product(bound_choices, repeat=L):
        for i, idx in enumerate(idxs):
            _l[idx] = bs[i][0]
            _r[idx] = bs[i][1]
        result = CVP(mat, _l, _r, sanity_check=True)
        if not result:
            continue
        for i in range(m):
            flag[26 - i] = result[i]
        if bytes_to_long(flag) % MOD == 0:
            print(flag)
            if check(flag.decode()):
                print("Found!")
                exit(0)
