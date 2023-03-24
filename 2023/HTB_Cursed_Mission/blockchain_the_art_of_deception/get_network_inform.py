from pwn import remote
io = remote("159.65.81.51", 31051, level='error')
io.sendlineafter(b'action? ', b'1')
io.recvline(0)
private_key = io.recvline(0).split(b':', 1)[-1].strip().decode()
address = io.recvline(0).split(b':', 1)[-1].strip().decode()
target = io.recvline(0).split(b':', 1)[-1].strip().decode()
setupContract = io.recvline(0).split(b':', 1)[-1].strip().decode()
io.close()

print(private_key)
print(setupContract)
