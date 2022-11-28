import string
from pwn import xor
ALPHA = string.ascii_lowercase.encode('utf8')

with open("out.txt",  "r") as file:
    enc_flag = file.readline()
    others = file.readlines()
    
enc_texts = []
for enc in others:
    enc_texts.append(bytes.fromhex(enc.strip('\n')))
enc_flag = bytes.fromhex(enc_flag.strip('\n'))

print(f"[+] {enc_flag = }\n")

def CheckText(char: bytes):
    return True if char in ALPHA else False
    

def TestAll(index: int, key: int):
    for enc_text in enc_texts:
        char = enc_text[index]
        plain = char ^ key
        if not CheckText(plain):
            return False
    return True

PREFIX = b"FLAG{"

key = b""

for i in range(len(enc_flag)):
    for c in range(256):
        if TestAll(i, c):
            key += bytes([c])
            print("[+] Found new part of key:", c)
            print(f"Key: {key}")
            break

print("\nFlag:", xor(enc_flag, key).decode('utf8'))