from   Crypto.Util.number  import *
from   Crypto.Cipher       import AES
from   Crypto.Util.Padding import pad
from   gmpy2               import next_prime
from   hashlib             import sha256
import random
flag = open("flag.txt", "rb").read()

def get_weak_prime(min_nbits):
    while True:
        p_1 = 2
        while p_1 < 2**min_nbits:
            p_1 *= int(next_prime(random.getrandbits(10)))
        p = p_1 + 1
        if isPrime(p):
            return p

p = get_weak_prime(512)
q = get_weak_prime(512)
n = p**11 * q**11

g = 3
a = random.randrange(0, n)
A = pow(g, a, n)
b = random.randrange(0, n)
B = pow(g, b, n)

print(f'{n = }')
print(f'{A = }')
print(f'{B = }')

ss1 = pow(A, b, n)
ss2 = pow(B, a, n)
assert ss1 == ss2

key = sha256(str(ss1).encode()).digest()
print(AES.new(
        key=key,
        mode=AES.MODE_ECB
    ).encrypt(pad(flag, 16)).hex())