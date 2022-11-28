# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2022.ductf.dev --port 30009 --color always
from ast import arg
from time import sleep
from pwn import connect, xor, process, args, log
host = args.HOST or '2022.ductf.dev'
port = int(args.PORT or 30009)

def start():
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return process(['python', 'ofb.py'])
    else:
        if args.DEBUG:
            level = "DEBUG"
        else:
            level = "INFO"
        return connect(host, port, level=level)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def encrypt(iv):
    io.sendlineafter(b'iv: ', iv.hex().encode('utf8'))
    m = io.recvline().strip(b'\n').decode('utf8')
    return bytes.fromhex(m)

io = start()
if args.LOCAL:
    print(io.recvline())
block1 = b'Decrypt this... '
iv1 = b'\0'*16
enc1 = encrypt(iv1)
iv2 = xor(block1, enc1[:16])
enc2 = encrypt(iv2)
io.close()
stream = xor(enc1, enc2)
real_stream = iv2
iv = iv2

for i in range(0, len(stream) - 16, 16):
    iv = xor(iv, stream[i:i+16])
    real_stream += iv

log.success(f'FLAG: {xor(real_stream, enc1)}')






