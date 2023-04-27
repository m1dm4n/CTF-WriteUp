from pwn import remote, process
from Crypto.Util.number import long_to_bytes
io = remote("challs.actf.co", 32100)
# io = process(["python", "lazylagrange.py"])
io.sendlineafter(b': ', b'1')
io.sendlineafter(b'> ', b'128')
ret = int(io.recvline(0))
ret = f"{ret:0126b}"
a = []
for i in range(18):
    a.append(int(ret[i*7:(i+1)*7], 2))
a = a[::-1]
print(a)
io.sendlineafter(b': ', b'2')
io.sendlineafter(b'> ', ' '.join(map(str, a)).encode())
p = list(map(int, io.recvline(0).strip().split()))
Flag = bytearray(18)
for idx, value in enumerate(p):
    Flag[value] = a[idx]
print(Flag.decode())