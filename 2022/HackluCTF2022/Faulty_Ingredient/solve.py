from Crypto.Cipher import AES
enc_flag = bytes([184, 141, 231, 192, 15, 156, 3, 102, 193, 58, 200, 246, 85, 33, 38, 129, 27, 123, 252, 39, 92, 205, 114, 108, 68, 138, 248, 113, 43, 1, 106, 146, 200, 78, 103, 89, 245, 15, 98, 72, 7, 218, 218, 109, 30, 107, 116, 130])
key = bytes.fromhex("25acfc955fa52864657da3c67384eef8")
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)
print(flag.decode('utf8'))
