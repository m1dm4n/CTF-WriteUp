from pwn import remote
from Crypto.Util.number import long_to_bytes

io = remote("challs.actf.co", 32400)

n = int(io.recvline(0).split(b' = ')[-1])
c = int(io.recvline(0).split(b' = ')[-1])
c = int(io.recvline(0).split(b' = ')[-1])


io.sendlineafter(b': ', str((-c)%n).encode())

m = int(io.recvline(0).split(b' = ')[-1])

print(long_to_bytes(-m % n))
