import string
def encrypt(c, prevc, i):
    x = (c + i * 0xf) % 0x80
    x += prevc % 128
    x ^= 0x555
    x = (x ^ ~0x0)  & 0xff
    x = ~(x ^ (0x3))
    x = ((x >> 0x1f) + x) ^ (x >> 0x1f)
    return x

alpha = string.printable
buffer = open('flag.txt', 'r', encoding='utf8').read()
pt = ""
prev = 0xd
for i in range(len(buffer)):
    for c in alpha:
        tmp = encrypt(ord(c), prev, i)
        if tmp == ord(buffer[i]):
            pt += c
            break
    prev = ord(buffer[i])
    
print(pt)
