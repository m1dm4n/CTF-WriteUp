s = bytes.fromhex(
    "cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b")


def b2(b):
    return (b ^ ((b >> 5) | (b << 3))) & 0xff


def b1(b):
    return (b ^ ((b << 1) | (b & 1))) & 0xff


def inv_b2(b):
    for i in range(32, 127):
        if b2(i) == b:
            return i


def decrypt(msg, c):
    a = c
    flag = bytes([a])
    for i in msg:
        b = (i - b1(a)) & 0xff
        b = inv_b2(b)
        if b == None:
            return None
        flag += bytes([b])
        a = b
    return flag


for c in range(32, 127):
    msg = s[:]
    flag = decrypt(msg, c)
    if flag:
        print(flag)
