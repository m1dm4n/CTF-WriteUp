from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
import sys
sys.path.insert(1, "/mnt/d/code/")
# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/branch_and_prune.py
from Helper.crypto_attacks.factorization.branch_and_prune import factorize_pqddpdq
from Helper.shared.partial_integer import PartialInteger

f1 = open('damaged_key.key', 'r').read().splitlines()[1:-1]
f1 = ''.join(f1).replace(" ", "?")
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
bin1 = ''
for char in f1:
    bin1 += "{:0>6b}".format(CHARS.index(char)) if char != '?' else '?'*6
# print(bin1, len(bin1))

def parse(payload, target_bit, l):
    return payload[target_bit:target_bit + l]

n_idx = 37
d_idx = 174
p_idx = 305
q_idx = 372
d1_idx = 438
d2_idx = 505
u_idx = 572

e = 0x10001
n = int(parse(bin1, n_idx*8, 128 * 8), 2)
d_bin = parse(bin1, d_idx*8, 128 * 8)
p_bin = parse(bin1, p_idx*8, 64 * 8)
q_bin = parse(bin1, q_idx*8, 64 * 8)
d1_bin = parse(bin1, d1_idx*8, 64 * 8)
d2_bin = parse(bin1, d2_idx*8, 64 * 8)

print(f"{d_bin = }", d_bin.count('?'))
print()
print(f"{p_bin = }", p_bin.count('?'))
print()
print(f"{q_bin = }", q_bin.count('?'))
print()
print(f"{d1_bin= }", d1_bin.count('?'))
print()
print(f"{d2_bin= }", d2_bin.count('?'))
print()

p, q = factorize_pqddpdq(
    n, 
    e,
    PartialInteger.parse_be(p_bin, 2),
    PartialInteger.parse_be(q_bin, 2),
    PartialInteger.parse_be(d_bin, 2),
    PartialInteger.parse_be(d1_bin, 2),
    PartialInteger.parse_be(d2_bin, 2),
)
# p = 11235982333858481957738882333839552787432968413673719367565182100760999937144642883191094443194544439840950002100069215403234921117088831978729766079053709
# q = 11205330818639163427193816398123121286517809290248085733293742402809227671039022556356406775564617099821555918144399477278649926821357427744215089861521347
print(f"{p = }")
print(f"{q = }")
assert p*q == n

d = inverse(e, (p-1)*(q-1))
flag_enc = open("access_key_enc.key", "rb").read()
ct = bytes_to_long(flag_enc)
print(long_to_bytes(pow(ct, d, n))[-42:].decode())
