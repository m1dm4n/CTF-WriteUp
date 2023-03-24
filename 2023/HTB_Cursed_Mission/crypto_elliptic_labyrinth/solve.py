from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from pwn import remote, process
import json
from sage.all import matrix, QQ
HOST = "165.232.108.240:30387"
io = remote(*(HOST.split(':')))
# io = process(['python', 'server.py'])
io.recvline()
A = json.loads(io.recvline(0))
xA = int(A['x'], 16)
yA = int(A['y'], 16)


def test(p, a, b, x, y):
    return (x**3 + a*x + b) % p == (y**2) % p


def solve(p, a, b, r, xA, yA):
    eq1 = (yA**2 - (xA**3 + xA * (a * 2**r) + (b * 2**r))) % p
    mat = matrix(QQ, [
        [eq1, 2**r, 0],
        [-xA, 0, 1],
        [p, 0, 0]
    ])
    for v in mat.LLL():
        a_low = int(abs(v[-1]))
        b_low = int(abs(v[0]))
        _a = (a * 2**r) + a_low
        _b = (b * 2**r) + b_low
        if test(p, _a, _b, xA, yA):
            return (_a, _b)
    return None


def get_flag(a, b):
    io.sendlineafter(b"> ", b'2')
    payload = json.loads(io.recvline(0))
    iv = bytes.fromhex(payload['iv'])
    enc = bytes.fromhex(payload['enc'])
    key = sha256(long_to_bytes(pow(a, b, p))).digest()[:16]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(enc)


while True:
    io.sendlineafter(b"> ", b'1')
    payload = json.loads(io.recvline(0))
    p = int(payload['p'], 16)
    _a = int(payload['a'], 16)
    _b = int(payload['b'], 16)
    r = 512 - _a.bit_length()
    print(f"Try {_a} - {_b}")
    for i in range(4):
        ans = solve(p, _a, _b, r - i, xA, yA)
        if ans:
            flag = get_flag(*ans)
            if b'HTB' in flag:
                print(unpad(flag, 16).decode())
                break
    else:
        continue
    print('Nice')
    break
