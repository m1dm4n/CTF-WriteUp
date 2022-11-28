from pwn import remote
io = remote("2022.ductf.dev", 30012, level="debug")
for i in range(3):
    io.recvline()
for i in range(3):
    io.sendline(b"0 0 0")
io.recvline()
io.close()