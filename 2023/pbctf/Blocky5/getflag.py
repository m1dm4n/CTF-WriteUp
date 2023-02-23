from Cipher import BlockCipher, INV_SBOX
from GF import GF

def round2master(rk):
    ret = [GF(i) for i in rk]
    for i in range(5 * 9):
        tmp = INV_SBOX[ret[8] - ret[7]]
        ret = [tmp] + ret
    return bytes([i.to_int() for i in ret[:9]])

rkey = bytes(list(map(int,  input().strip().split())))
enc_flag = bytes.fromhex(open("enc_flag.txt", "r").read().strip())
key = round2master(rkey)
print(key)
flag_cipher = BlockCipher(key, 20)
flag = b''
for i in range(0, len(enc_flag), 9):
    flag += flag_cipher.decrypt(enc_flag[i:i+9])
print(flag.strip().decode())