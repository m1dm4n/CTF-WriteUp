from sage.all import ComplexField, matrix, round
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
f = open("output.txt").read().splitlines()
bits = 1111
C = ComplexField(bits)
r = C(f[0])
enc = bytes.fromhex(f[1])
real = [(r ** i)[0] for i in range(16)]
imag = [(r ** i)[1] for i in range(16)]
K = 2 ** (bits - 1)
M = matrix([[round(K * x) for x in real], [round(K * x) for x in imag]]).T.augment(
    matrix.identity(16)
)
M = M.LLL()[0, 2:].list()
print(M)

key = []
for i in M:
    key.append(int(abs(i)).to_bytes(16, 'little'))

key = sha256(b''.join(key)).digest()
cipher = AES.new(key, AES.MODE_CBC, iv=enc[:16])
flag = unpad(cipher.decrypt(enc[16:]), 16)
print(flag.decode())