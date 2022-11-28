
from z3 import *
from Crypto.Util.number import *
from sage.all import matrix

header = bytes.fromhex("89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52".replace(" ", ""))


def matrix2bytes(m):
    ret = b''
    for i in range(4):
        for j in range(4):
            ret += bytes([int(m[i][j])])
    return ret
def bytes2matrix(b):
	return [list(map(lambda x: x, list(b[i:i+4]))) for i in range(0, len(b), 4)]

def _bytes2matrix(b):
    tmp = [b[i:i+8] for i in range(0, len(b), 8)]
    ret = [[]]
    for i in range(4):
        for j in range(0, 8, 2):
            ret[-1].append(int.from_bytes(tmp[  i][j:j+2], 'big'))
        ret.append([])
    ret.pop(-1)
    return ret


header = matrix(bytes2matrix(header))


data = open("flag.png.enc", "rb").read()

block1 = matrix(_bytes2matrix(data[:32]))


key = header.solve_right(block1)
flag = open("flag.png", "wb")
for i in range(0, len(data), 32):
    block = matrix(_bytes2matrix(data[i:i+32]))
    dec = key.solve_left(block)
    flag.write(matrix2bytes(dec))

flag.close()

