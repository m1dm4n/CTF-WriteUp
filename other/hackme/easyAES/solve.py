import base64
from Crypto.Cipher import AES  # pip3 install pycrypto

def main(data):
    c = AES.new(b'Hello, World...!', AES.MODE_ECB)
    plain_text = c.decrypt(b'Good Plain Text!')
    if c.encrypt(plain_text) != b'Good Plain Text!':
        print('Bad plain text')
        exit()

    c2 = AES.new(plain_text[::-1], mode=AES.MODE_CBC, IV=b'1234567887654321')

    decrypted = c2.decrypt(data)

    with open('output.jpg', 'wb') as fout:
        fout.write(decrypted)


main(base64.b64decode(open("D:\code\ctf\hackme\out", "r").read()))
