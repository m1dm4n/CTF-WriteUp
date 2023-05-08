from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex(
    "c9a391c6f65bbb38582044fd78143fe72310e96bf67401039b3b6478455a1622")
data = open('./ciphertext.bin', 'rb').read()
cip = AES.new(key, AES.MODE_CBC, iv =data[:16])

print(unpad(cip.decrypt(data[16:]), 16)[-60:])
# HCMUS-CTF{it5_c4ll3d_pr1v4t3_k3y_crypt09raphy_f0r_4_r3450n}
