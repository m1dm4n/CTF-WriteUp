from pwn import *
import os
from math import ceil
from Crypto.Util.number import bytes_to_long
from random import getrandbits
io = remote('34.175.151.38', 5001)

ret = io.recvline().decode().split(' ')
num = int(ret[3][:-1], 16)
print(hex(num))
bit = ceil(num.bit_length()//8) * 8
a = getrandbits(bit)
b = getrandbits(bit)
c = num ^ a ^ b
assert a^b^c == num
io.sendline(str(a).encode())
io.sendline(str(b).encode())
io.sendline(str(c).encode())
io.sendline(b'Stop')
io.interactive()