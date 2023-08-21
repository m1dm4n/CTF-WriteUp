# I just want to put this code here, to remind myself
# not to accientally have any os.urandom() calls in 
# this script...
import pyseccomp
filter = pyseccomp.SyscallFilter(defaction=pyseccomp.ALLOW)
filter.add_rule(pyseccomp.ERRNO(1), 'getrandom')
filter.load()

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
import random

def get_encrypted_flag():
    key        = random.randbytes(16)
    iv         = random.randbytes(16)
    plaintext  = pad(open('flag.txt', 'rb').read(), 16)
    ciphertext = AES.new(
                     key=key,
                     iv=iv,
                     mode=AES.MODE_CBC
                 ).encrypt(plaintext)

    print(f'key        = u?\' cho')
    print(f'iv         = u?\' cho')
    print(f'plaintext  = u?\' cho')
    print(f'ciphertext = {ciphertext.hex()}')

def get_encrypted_data():
    key        = random.randbytes(16)
    iv         = random.randbytes(16)
    plaintext  = random.randbytes(16)
    ciphertext = AES.new(
                     key=key,
                     iv=iv,
                     mode=AES.MODE_CBC
                 ).encrypt(plaintext)

    print(f'key        = {key.hex()}')
    print(f'iv         = {iv.hex()}')
    print(f'plaintext  = {plaintext.hex()}')
    print(f'ciphertext = {ciphertext.hex()}')

print("Too lazy to invent an introduction :( But you know the drill :)")
while True:
    print(f'---------------------------------------------------------')
    print(f'     1. Get encrypted datas.')
    print(f'     2. Get encrypted flag.')
    print(f'     3. Get nothing, say bye bye.')
    print(f' other. Get error.')
    print(f'---------------------------------------------------------')

    try:
        user_input = int(input('> '))
        match user_input:
            case 1:
                random = random.Random()
                while True:
                    if input('> more? (y/not y) ').lower() != 'y':
                        break
                    get_encrypted_data()
            case 2:
                random.seed(int(time.time() * 10**6))
                get_encrypted_flag()
            case 3:
                break
            case _:
                assert False

    except KeyboardInterrupt as e:
        print('cau co the an 3 ma, nhung the nay exit cung duoc UwU')
        break

    except:
        print('huhu cau lam gi the to bi error mat roi')
        break