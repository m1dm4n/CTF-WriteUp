import sys
from pwn import remote, process, args
from sage.all_cmdline import gcd, Zmod, PolynomialRing, factor
from Crypto.Util.number import long_to_bytes


if args.LOCAL:
    io = process(["python", "romeo_and_juliet.py"])
    e = 3083
else:
    io = remote("win.the.seetf.sg", 3001)
    e = 65537

def query(n):
    io.sendlineafter(b"yells: ", str(n).encode())
    return int(io.recvline(0).decode().split()[-1])

enc = int(io.recvline(0).decode().split()[-1])

# need n1 < n2 to work, 50/50 
# Get n1
c2 = query(query(-1))
n1 = int(c2+1)


# Get n2
c1 = query(pow(2, e, n1))
query(0)
c2 = query(pow(3, e, n1))
query(0)
n2 = gcd(2**e - c1, 3**e - c2)
n2 = int(list(factor(n2, limit=2**20))[-1][0])

# Sanity check
assert n1 < n2
assert n1.bit_length() >= 1020 and n2.bit_length() >= 1020


# Find k such that 2**k * flag overflow n2 so that we will have c2 = (2**k*flag - n2)**e
l = 1
r = 1024
for _ in range(12):
    k = (l + r)//2
    c2 = query(query(enc) * pow(2, e*k, n2))
    if (c2 == ((enc * pow(2, e*k, n1)) % n1)):
        l = k+1
    else:
        r = k
k = l
print(k)

# Get (flag - n2)**e % n1
c2 = query(query(enc) * pow(2, e*k, n2))
io.close()


# Find gcd(x**e - c1, (x*2**k-n2)**e - c2)
sys.path.insert(1, "/mnt/d/code/Helper/")
from shared.polynomial import fast_polynomial_gcd

P, x = PolynomialRing(Zmod(n1), 'x').objgen()
x = P.gen()
f1 = x**e - enc
f2 = (x*(2**k) - n2) ** e - c2
flag = (-fast_polynomial_gcd(f1, f2).list()[0]) % n1
assert flag != n1 - 1
print(long_to_bytes(int(flag)))
