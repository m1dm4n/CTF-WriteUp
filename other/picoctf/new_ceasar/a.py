import string
enc = "kjlijdliljhdjdhfkfkhhjkkhhkihlhnhghekfhmhjhkhfhekfkkkjkghghjhlhghmhhhfkikfkfhm"

ALPHABET = string.ascii_lowercase[:16]
LOWERCASE_OFFSET = ord("a")

def inv_shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]

def b16_decode(b16:str):
    flag = ""
    for i in range(0, len(b16), 2):
        c = ""
        c += "{0:04b}".format(ALPHABET.index(b16[i]))
        c += "{0:04b}".format(ALPHABET.index(b16[i+1]))
        flag += chr(int(c, 2))
    return flag
    
def check(text:str):
    for c in text:
        if not c.isalnum() and c not in "_}{-=*!/?" :
            return False
    return True

for k in ALPHABET:
    key = k
    flag = ""
    for i, c in enumerate(enc):
        flag += inv_shift(c, key[i % len(key)])
    flag = b16_decode(flag)
    if check(flag): 
        print("Flag:", "picoCTF{" + flag + "}")

