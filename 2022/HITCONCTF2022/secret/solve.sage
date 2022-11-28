from Crypto.Util.number import *
from itertools import combinations
from gmpy2 import gcd, mpz
from sage.all import matrix, ZZ, block_matrix
from ast import literal_eval
import logging

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)
line = open('output.txt', 'r').read().splitlines()
es = literal_eval(line[0])
cs = list(map(mpz, literal_eval(line[1])))

def compute(coff):
    pos = mpz(1)
    neg = mpz(1)
    for i, cof in enumerate(coff[1:]):
        if cof > 0:
            pos = pos * cs[i]**cof
        else:
            neg = neg * cs[i]**(-cof)
    if coff[0] > 0:
        return ZZ(pos)/ZZ(neg)
    else:
        return ZZ(neg)/ZZ(pos)

def solve(ess, bit_need):
    L = len(ess)
    M1 = matrix.identity(ZZ, L)
    mates = matrix(ZZ, L, 1)
    for i, e in enumerate(ess):
        mates[i, 0] = e
    mat = block_matrix(ZZ, [mates, M1], ncols=2)
    mat = mat.LLL()
    # for row in mat:
    #     logging.info(row)
    ns = []
    for row1, row2 in combinations(list(mat.rows()), 2):
        a, b = abs(row1[0]), abs(row2[0])
        k1, k2 = 1, 1
        if a % b == 0:
            k2 *= a // b
        elif b % a == 0:
            k1 *= b // a
        else:
            continue
        try:
            logging.info(f"Found a good pair: a = {row1[0]}, b = {row2[0]}")
            k1 = compute(row1)**k1
            k2 = compute(row2)**k2
            ns.append(mpz((k1 - k2).numerator()))
        except ValueError:
            continue
        if len(ns) > 2:
            p = gcd(*ns)
            logging.debug(f"Found a gcd with {p.bit_length()} bits")
            if p.bit_length() <= bit_need:
                return p
    return p


# find p
new_es = []
for e in es:
    new_es.append(e + 1)
p = solve(new_es, 1024)
logging.debug(f"Found p: {p}")
# p = 114123489471785231935784934808971699969409921187241213856052699152350022529522625133249122600992294384493330729753558097354310956450782137388609095123051712848950720360020186805006589596948820312938610934162552701552428320073591829720623902109809701883779673050594202312941073709061911680769616320309646800153

# find n
new_es = []
for e in es:
    new_es.append(e + p)
n = solve(new_es, 2048)
logging.debug(f"Found n: {n}")

# n = 17724789252315807248927730667204930958297858773674832260928199237060866435185638955096592748220649030149566091217826522043129307162493793671996812004000118081710563332939308211259089195461643467445875873771237895923913260591027067630542357457387530104697423520079182068902045528622287770023563712446893601808377717276767453135950949329740598173138072819431625017048326434046147044619183254356138909174424066275565264916713884294982101291708384255124605118760943142140108951391604922691454403740373626767491041574402086547023530218679378259419245611411249759537391050751834703499864363713578006540759995141466969230839

q = n//p
phi = (p-1)*(q-1)
for e in es:
    if gcd(p+e, phi) != 1:
        continue
    d = inverse(p+e, phi)
    logging.debug("FLAG: hitcon{" + long_to_bytes(
        pow(cs[es.index(e)], d, n)).split(b'hitcon{')[-1].decode().strip())
    break
