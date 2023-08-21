from Crypto.Util.number import *

g = 0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004b
p = getPrime(256)           # secret_key
q = getPrime(256)           
n = p*q

def pad(msg):
    msg += b'\xff' * (64 - len(msg) % 64)
    return msg

def encrypt(msg, p, n):
    q = n // p
    msg = pad(msg)
    l = len(msg)
    enc = b''
    leak = []
    for i in range(l//64):
        m = bytes_to_long(msg[64*i: 64*(i+1)])
        leak.append(m*q % g)
        enc += long_to_bytes((m*n%g) ^ p, blocksize=64)
    return leak, enc



with open('flag.txt', 'rb') as f:
    msg = f.read()

leak, enc = encrypt(msg, p, n)

print(f"n = {n}")
print(f'leak = {leak}')
print(f"enc = '{enc.hex()}'")


