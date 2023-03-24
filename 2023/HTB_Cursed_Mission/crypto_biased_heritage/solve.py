from secrets import randbelow
from hashlib import sha256
from sage.all import QQ, matrix
from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long

from pwn import process, remote
io = process(['python', 'server.py'])
# io = remote('104.248.169.157', 32351)


# def H(msg):
#     return bytes_to_long(2 * sha256(msg).digest()) % q
def H(msg):
    return (2**256 + 1) * bytes_to_long(sha256(msg).digest()) % q


def sign(msg, x):
    k = H(msg + long_to_bytes(x))
    r = pow(g, k, p) % q
    e = H(long_to_bytes(r) + msg)
    s = (k - x * e) % q
    return (s, e)


p = 0x184e26a581fca2893b2096528eb6103ac03f60b023e1284ebda3ab24ad9a9fe0e37b33eeecc4b3c3b9e50832fd856e9889f6c9a10cde54ee798a7c383d0d8d2c3
q = (p - 1) // 2
g = 3
io.recvline()
y = int(io.recvline(0)[3:])
io.recvline()


def get_payload():
    rets = []
    for i in range(2):
        io.sendlineafter(b'> ', b'S')
        io.sendlineafter(b'> ', long_to_bytes(i).hex().encode())
        rets.append(eval(io.recvline(0).split(b": ")[-1]))
    return rets


def get_flag(x):
    s, e = sign(b'right hand', x)
    io.sendlineafter(b'> ', b'V')
    io.sendlineafter(b'> ', b'right hand'.hex().encode())
    io.sendlineafter(b'> ', str(s).encode())
    io.sendlineafter(b'> ', str(e).encode())
    io.interactive()


(s1, e1), (s2, e2) = get_payload()
const = pow(2**256 + 1, -1, q)
mat = matrix(QQ, [
    [q, 0, 0, 0],
    [0, q, 0, 0],
    [(e1 * const) % q, (e2 * const) % q, 1/QQ(2**256), 0],
    [(s1 * const) % q, (s2 * const) % q, 0, QQ(2**256)]
])

for i in mat.LLL():
    cur_x = int(abs(i[-2] * QQ(2**256)))
    print(cur_x)
    for cur_x in range(cur_x - 1000, cur_x + 1000):
        if pow(g, cur_x, p) == y:
            x = cur_x
            get_flag(x)
else:
    print("Nope!")
