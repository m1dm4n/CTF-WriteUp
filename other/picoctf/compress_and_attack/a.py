from pwn import *
import string
sh = remote("mercury.picoctf.net", 2431)


def oracle(text):
    sh.recvuntil(b"encrypted:")
    sh.sendline(bytes(text, 'utf8'))
    sh.recvline()
    sh.recvline()
    return int(sh.recvline().decode())


known = "picoCTF{sheriff_you_"
length = oracle(known)
abc = string.ascii_lowercase + string.ascii_uppercase + "_}"
current = ""
while current != "}":
    for c in abc:
        if oracle(known + c) == length:
            known += c
            current = c
            print(known)
            break
