from pwn import *

with open('D:\code\ctf\picoctf\XtraORdinary\output.txt', 'r') as f:
    encode_text = bytes.fromhex(f.read())

random_strs = [b'my encryption method', b'is absolutely impenetrable', b'and you will never', b'ever', b'break it']

def check (text:str):
    for c in text:
        if not c.isalnum() and c not in "{}_?+=-!.@#%":
            return False
    return True

for i in range(32):
    tmp = encode_text
    perm = "{0:05b}".format(i)
    for i in range (5):
        if perm[i] == "1":
            tmp = xor(tmp, random_strs[i])
    flag_prefix = b"picoCTF"
    key = xor(tmp[:7], flag_prefix)
    try:
        if check(key.decode()):
            flag = xor(tmp,key).decode()
            if (check(flag)):
                print(perm)
                print(flag)
    except: 
        continue