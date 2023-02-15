from pwn import remote
io = remote("lac.tf", 31150, level='error')
io.sendlineafter(b'action? ', b'1')
io.recvuntil(b'information\n\n')

uuid = io.recvline(0).split(b':', 1)[-1].strip().decode()
rpc = io.recvline(0).split(b':', 1)[-1].strip().decode()
private_key = io.recvline(0).split(b':', 1)[-1].strip().decode()
setupContract = io.recvline(0).split(b':', 1)[-1].strip().decode()
io.close()

print(uuid)
print(rpc)
print(private_key[2:])
print(setupContract)
