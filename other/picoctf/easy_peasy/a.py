from pwn import *

r = remote("mercury.picoctf.net", 20266)

cipher =bytes.fromhex("5b1e564b6e415c0e394e0401384b08553a4e5c597b6d4a5c5a684d50013d6e4b")
LEN = 50000
a = 32
res = r.recvuntil(b"What data would you like to encrypt?").decode()
print(res)

while a < LEN:
    n = min(1000, LEN - a)
    r.sendline(bytes(("a"*n), "utf8"))
    r.recvuntil(b"What data would you like to encrypt?")
    a += n
    log.progress(f"Sending ({a}/{LEN})")

log.success("Complete!!!")
r.sendline(cipher)
res = r.recvuntil(b"What data would you like to encrypt?").decode()
flag = res.split("Here ya go!\n")[1].split("\n")[0]
log.success("Flag: picoCTF{" + bytes.fromhex(flag).decode() + "}")

r.close()