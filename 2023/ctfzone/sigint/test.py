from base64 import b64decode as b64d
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
import sys
import logging
from sage.all import *

f1 = open('damaged_key.key', 'r').read().splitlines()[1:-1]
f2 = open('sample.pem', 'r').read().splitlines()[1:-1]
f1 = ''.join(f1).replace(" ", "?")
f2 = ''.join(f2)[:-2]


CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# ## bin1
bin1 = ''
for char in f1:
    bin1 += "{:0>6b}".format(CHARS.index(char)) if char != '?' else '?'*6
# print(bin1, len(bin1))
# exit(0)
# ###
# bin2
bin2 = ''
for char in f2:
    bin2 += "{:0>6b}".format(CHARS.index(char))
bin2 = bin2[:-4]
# print(bin2, len(bin2))
# exit(0)
###

# key1 = b64d(f1.replace('?', 'A'))
key2 = b64d(f2 + "==")
testkey = RSA.importKey(open('sample.pem', 'r').read())

n_idx = key2.index(long_to_bytes(testkey.n))
d_idx = key2.index(long_to_bytes(testkey.d))
p_idx = key2.index(long_to_bytes(testkey.p))
q_idx = key2.index(long_to_bytes(testkey.q))
d1_idx = key2.index(long_to_bytes(testkey.d % (testkey.p-1)))
d2_idx = key2.index(long_to_bytes(testkey.d % (testkey.q-1)))
# u_idx = key2.index(long_to_bytes(inverse(testkey.q, testkey.p)))


print(f"{n_idx = }") 
print(f"{d_idx = }") 
print(f"{p_idx = }") 
print(f"{q_idx = }") 
print(f"{d1_idx = }")
print(f"{d2_idx = }")
# print(f"{u_idx = }")
e_idx = key2.index(long_to_bytes(testkey.e))
def parse(payload, target_bit, l):
    return payload[target_bit:target_bit + l]
print(parse(bin2, d1_idx*8 - 32 , 80))
print()


n_idx = 37
d_idx = 174
p_idx = 305
q_idx = 372
d1_idx = 438
d2_idx = 505
print(f"{n_idx = }") 
print(f"{d_idx = }") 
print(f"{p_idx = }") 
print(f"{q_idx = }") 
print(f"{d1_idx = }")
print(f"{d2_idx = }")
print(parse(bin1, d1_idx*8 - 32, 80))