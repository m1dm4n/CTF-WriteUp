import os
import random
from sage.all import ComplexField, PolynomialRing
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256

bits = 1111
C = ComplexField(bits)
P = PolynomialRing(C, names='x')
(x,) = P.gens()
key = os.urandom(256)
coeff = [int.from_bytes(key[i:i+16], 'little') for i in range(0, len(key), 16)]
f = sum([a * x ** i for i, a in enumerate(coeff)])
r = random.choice(f.roots())[0]
# One is enough. Don't greedy!
print(r)
# print(coeff)

# AES
_key = sha256(key).digest()
iv = os.urandom(16)
cipher = AES.new(_key, AES.MODE_CBC, iv=iv)
enc = iv + cipher.encrypt(pad(open('flag.txt', 'rb').read(), 16))
print(enc.hex())