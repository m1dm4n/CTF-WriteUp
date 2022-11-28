from pwn import remote


flag = "184aed743987e240d2715d41fa0d450aa3ac24aecce9dbc5e86d5f69aa1677d2"
flag = flag[16:32] + flag[:16] + flag[48:] + flag[32:48]
print(flag)
io = remote("flu.xxx", 12001)
io.sendlineafter(b"\n", flag.encode())
dec = io.recv(4096).strip().split(b': ')[-1].decode()
io.close()
dec = dec[16:32] + dec[:16] + dec[48:] + dec[32:48]
print(dec)
print(bytes.fromhex(dec).decode())
