from pwn import remote
import re
from Crypto.Cipher import AES
import string
import random
# key = b"XXXXXXXXXXXXXXXX"
# iv = ''.join(random.choice(string.hexdigits) for _ in range(16))
# iv = iv.encode()
# def encrypt(p):
#     return AES.new(key, AES.MODE_OFB, iv).encrypt(p.encode())


# print(len(encrypt(''.join(random.choice(string.ascii_lowercase) for _ in range(30)))))


io = remote("ctf.hackme.quest", 7700)
def gethex():
    res = io.recvuntil(b"(Press any key to continue)\n").decode()
    enc = re.findall(r"[0-9a-f]+\n", res)[0].strip('\n')
    io.send(b"\n")
    return enc

while True:
    print(gethex())
