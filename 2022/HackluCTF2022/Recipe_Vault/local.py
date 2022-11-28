
import numpy as np
import binascii
from pwn import log
some_table = np.zeros(256, dtype=int)


def byteof(d, i):
    return (d >> (i * 8)) & 0xff


def mystery(x):
    y = np.zeros(4, dtype=int)
    y[0] = some_table[byteof(x[0], 0) ^ some_table[byteof(x[2], 0)]] | (some_table[byteof(x[2], 0) ^ some_table[byteof(x[0], 0)]] << 8) | (
        some_table[byteof(x[0], 1) ^ some_table[byteof(x[2], 1)]] << 16) | (some_table[byteof(x[2], 1) ^ some_table[byteof(x[0], 1)]] << 24)

    y[1] = some_table[byteof(x[0], 2) ^ some_table[byteof(x[2], 2)]] | (some_table[byteof(x[2], 2) ^ some_table[byteof(x[0], 2)]] << 8) | (
        some_table[byteof(x[0], 3) ^ some_table[byteof(x[2], 3)]] << 16) | (some_table[byteof(x[2], 3) ^ some_table[byteof(x[0], 3)]] << 24)

    y[2] = some_table[byteof(x[1], 0) ^ some_table[byteof(x[3], 0)]] | (some_table[byteof(x[3], 0) ^ some_table[byteof(x[1], 0)]] << 8) | (
        some_table[byteof(x[1], 1) ^ some_table[byteof(x[3], 1)]] << 16) | (some_table[byteof(x[3], 1) ^ some_table[byteof(x[1], 1)]] << 24)

    y[3] = some_table[byteof(x[1], 2) ^ some_table[byteof(x[3], 2)]] | (some_table[byteof(x[3], 2) ^ some_table[byteof(x[1], 2)]] << 8) | (
        some_table[byteof(x[1], 3) ^ some_table[byteof(x[3], 3)]] << 16) | (some_table[byteof(x[3], 3) ^ some_table[byteof(x[1], 3)]] << 24)
    return y


def mystery2(x):
    y = np.zeros(4, dtype=int)
    y[0] = byteof(x[0], 0) | (byteof(x[0], 2) << 8) | (
        byteof(x[1], 0) << 16) | (byteof(x[1], 2) << 24)
    y[1] = byteof(x[2], 0) | (byteof(x[2], 2) << 8) | (
        byteof(x[3], 0) << 16) | (byteof(x[3], 2) << 24)
    y[2] = byteof(x[0], 1) | (byteof(x[0], 3) << 8) | (
        byteof(x[1], 1) << 16) | (byteof(x[1], 3) << 24)
    y[3] = byteof(x[2], 1) | (byteof(x[2], 3) << 8) | (
        byteof(x[3], 1) << 16) | (byteof(x[3], 3) << 24)
    return y


def magic(x):
    v = mystery2(mystery(mystery(mystery(mystery(x)))))
    u = np.zeros(4, dtype=int)
    u[0] = x[0] ^ v[0]
    u[1] = x[1] ^ v[1]
    u[2] = x[2] ^ v[2]
    u[3] = x[3] ^ v[3]
    v = mystery2(mystery(mystery(mystery(mystery(u)))))
    u[0] = x[0] ^ v[0]
    u[1] = x[1] ^ v[1]
    u[2] = x[2] ^ v[2]
    u[3] = x[3] ^ v[3]
    v = mystery2(mystery(mystery(mystery(mystery(u)))))
    v[2] = x[2]
    v[3] = x[3]
    return v


def init_some_table():
    f = 1
    for i in range(0, 255):
        some_table[i] = f & 0xff
        f <<= 1
        if f > 0xff:
            f ^= 0x0165


def transform_key(in_key):
    init_some_table()
    something_key = np.zeros(12, dtype=int)
    something_key[0] = in_key[0]
    something_key[1] = in_key[1]
    something_key[2] = in_key[0]
    something_key[3] = in_key[1]
    something_key[4] = in_key[2]
    something_key[5] = in_key[3]
    something_key[6] = in_key[2]
    something_key[7] = in_key[3]
    something_key[8] = in_key[0]
    something_key[9] = in_key[1]
    something_key[10] = in_key[0]
    something_key[11] = in_key[1]
    return something_key


def combination_magic(x, y, k):
    tt = np.zeros(4, dtype=int)
    retval = np.zeros(2, dtype=np.uint32)
    tt[0] = y[0]
    tt[1] = y[1]
    tt[2] = k[0]
    tt[3] = k[1]
    tt = magic(tt)
    retval[0] = x[0] ^ tt[0]
    retval[1] = x[1] ^ tt[1]
    return retval


def encrypt(blk, something_key):
    blk = np.copy(blk)
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[0:2])
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[2:4])
    # log.info(str(blk))
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[4:6])
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[6:8])
    # log.info(str(blk))
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[8:10])
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[10:12])

    return blk


def decrypt(blk, something_key):
    blk = np.copy(blk)
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[2:4])
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[0:2])

    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[6:8])
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[4:6])

    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[10:12])
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[8:10])

    return blk

some_table = np.zeros(256, dtype=int)

buf = (b"abcd"*2 + b"xyzt"*2).hex()

try:
    in_file = open("key_test.bin", "rb")
except:
    print("Key not found, terminating")
    exit(-1)
key_bytes = in_file.read(128)
key = np.frombuffer(key_bytes, dtype=np.uint32)
in_file.close()
mkey = transform_key(key)
print(f"Key: {mkey}")
encrypted_full = ""
rawbytes = bytes.fromhex(buf)
cleartext = np.frombuffer(rawbytes, dtype=np.uint32)
print(f"plaintext  = {cleartext.tolist()}")
ciphertext = encrypt(cleartext, mkey)
print(f"ciphertext = {ciphertext.tolist()}")
encrypted_full += binascii.hexlify(ciphertext).decode('ascii')
print(f"{encrypted_full = }")

e = bytes.fromhex(encrypted_full)
c = np.frombuffer(e, dtype=np.uint32)

print(f"plaintext' = {decrypt(c, mkey)}")
