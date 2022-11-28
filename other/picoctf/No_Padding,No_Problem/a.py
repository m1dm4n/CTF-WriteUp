from Crypto.Util.number import long_to_bytes
from pwn import *

r = remote("mercury.picoctf.net", "30048")
###
b= r.recvuntil(b"decrypt: ").decode().strip()
print(b)
log.progress('Getting n, e, c')
lit = b.split("\n")
n = int(lit[4].split(' ')[1])
e = int(lit[5].split(' ')[1])
c = int(lit[6].split(' ')[1])
log.progress(f'Sending c + n = {c + n}')
r.send((str(c + n)+"\n").encode())
result = r.recvline().decode()
print()
print(result)
plain = int(result.split(": ")[1])
###

log.success(f"Flag: {long_to_bytes(plain).decode()}")