from Crypto.Cipher import AES


key = bytes.fromhex(
    "c9a391c6f65bbb38582044fd78143fe72310e96bf67401039b3b6478455a1622")
data = open('./ciphertext.bin', 'rb').read()
cip = AES.new(key, AES.MODE_CBC, iv =data[:16])

print(cip.decrypt(data[16:])[-67:])