import logging
import os
import sys
from gmpy2 import mpz, powmod, is_prime, next_prime, kronecker, gcd 

from sage.all import crt, prod


def _generate_s(A, k):
    S = []
    for a in A:
        S.append(set([1, a + 1, 2*a + 1, 3*a + 1]))

    return S


# Brute forces a combination of residues from S by backtracking
# X already contains the remainders mod each k
# M already contains each k
def _backtrack(S, A, X, M, i):
    if i == len(S):
        return int(crt(X, M)), prod(M)

    M.append(4 * A[i])
    for za in S[i]:
        X.append(za)
        try:
            crt(X, M)
            z, m = _backtrack(S, A, X, M, i + 1)
            if z is not None and m is not None:
                return z, m
        except ValueError:
            pass
        X.pop()

    M.pop()
    return None, None


def generate_pseudoprime(A, k2=None, k3=None, min_value=0, cap=100000):
    """
    Generates a pseudoprime of the form p1 * p2 * p3 which passes the Miller-Rabin primality test for the provided bases.
    More information: R. Albrecht M. et al., "Prime and Prejudice: Primality Testing Under Adversarial Conditions"
    :param A: the bases
    :param k2: the k2 value (default: next_prime(A[-1]))
    :param k3: the k3 value (default: next_prime(k2))
    :param min_bit_length: the minimum bit length of the generated pseudoprime (default: 0)
    :return: a tuple containing the pseudoprime n, as well as its 3 prime factors
    """
    A.sort()
    if k2 is None:
        k2 = mpz(next_prime(A[-1]))
    if k3 is None:
        k3 = mpz(next_prime(k2))
    while True:
        logging.info(f"Trying k2 = {k2} and k3 = {k3}...")
        X = [powmod(-k3, -1, k2), powmod(-k2, -1, k3)]
        M = [k2, k3]
        S = _generate_s(A, M)
        logging.info(f"S = {S}")
        z, m = _backtrack(S, A, X, M, 0)
        if z and m:
            logging.info(f"Found residue {z} and modulus {m}")
            i = min_value
            while True:
                p1 = mpz(z + i * m)
                p2 = k2 * (p1 - 1) + 1
                p3 = k3 * (p1 - 1) + 1
                if is_prime(p1) and is_prime(p2) and is_prime(p3):
                    return int(p1 * p2 * p3), int(p1), int(p2), int(p3)

                i += 1
        else:
            k3 = next_prime(k3)
            if k3 > cap:
                k2 = next_prime(k2)
                k3 = next_prime(k2)
            if k2 > cap:
                return None, None, None, None
            
