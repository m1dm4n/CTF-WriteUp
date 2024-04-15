import logging
from primes import generate_pseudoprime
from sage.all import *
logging.basicConfig(level=10)
load("chall.sage")
ms = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
cc, p, q, r = generate_pseudoprime(ms, cap=1000)
print(cc, p)
assert is_prime(cc)