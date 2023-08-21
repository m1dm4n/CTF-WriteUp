import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random

initkey = [1460716094, 678072110, 4793, 1460717254, 678072110]
t = ((initkey[1] << 32) + initkey[0]) // 10**9
ct = 'da4bfea5a55e83c9f9ffc08451cbe2856d322b18e6d3a8c61f5cfd5878a6ad168bf5ecae37d8df7d76a0778a5886ae952062d2c5aa29056529514eff998e18ae\n'
ct = bytes.fromhex(ct)

for i in range(10**6):
    random.seed(t * 10**6 + i)
    key = random.randbytes(16)
    iv = random.randbytes(16)
    ciphertext = AES.new(
        key=key,
        iv=iv,
        mode=AES.MODE_CBC
    ).decrypt(ct)
    if b"BKSEC" in ciphertext:
        print(unpad(ciphertext, 16))
        break
