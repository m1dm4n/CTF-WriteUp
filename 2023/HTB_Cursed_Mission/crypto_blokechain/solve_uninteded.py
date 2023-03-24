import re
from pwn import process, remote

def get_payload():
    io.sendline(b"1")
    io.sendlineafter(b"vessels\n", b"2")
    io.sendline(suss_nums)
    lines = io.recvuntil(b'vessels\n')
    lines = lines[lines.index(b"expected"):]
    hs = []
    for line in lines.splitlines()[:-5]:
        nums = re.findall(b" [a-f\d]+", line)
        hs.append(int(nums[0].strip(), 16))
    io.sendline(b"2")
    io.sendline(b'\n'.join(str(h).encode() for h in ([0] * (60-len(hs)) + hs) ))


# change this if you spawn a new docker
io = remote(*("68.183.45.143:32297".split(':')), level='error')
# io = process(['python', 'server.py'])
io.recvuntil(b'vessels\n')
print('start')
suss_nums = b'\n'.join(b'1' for _ in range(60))
samples = []

while True:
    get_payload()
    ret = io.recvuntil(b'vessels\n')
    bal_idx = ret.index(b"Balance")
    ret = ret[bal_idx:]
    balance = int(ret.splitlines()[0].split(b': ')[-1])
    print(balance)
    if balance > 100000000:
        break
io.sendline(b"3")
io.interactive()
 