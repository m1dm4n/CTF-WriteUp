from Cipher import BlockCipher, INV_SBOX
from itertools import product
from GF import GF
data = open('output.txt', 'r').read().splitlines()
enc_flag = bytes.fromhex(data[0])
ciphertexts = [bytes.fromhex(d) for d in data[1:]]


def backup(ct, byteGuess, byteIndex):
    t = GF(ct[byteIndex]) - GF(byteGuess)
    return INV_SBOX[t]


def integrate(index):
    potential = []

    for candidateByte in range(243):
        sum = GF(0)
        for ciph in ciphertexts:
            oneRoundDecr = backup(ciph, candidateByte, index)
            sum += oneRoundDecr
        # print(sum)
        if sum == GF(0):
            potential.append(candidateByte)
    # exit(1)
    return potential


def round2master(rk):
    ret = [GF(i) for i in rk]
    for i in range(4 * 9):
        tmp = INV_SBOX[ret[8] - ret[7]]
        ret = [tmp] + ret
    return bytes([i.to_int() for i in ret[:9]])


def integral():
    candidates = []
    for i in range(9):
        candidates.append(integrate(i))
    print('candidates', candidates)
    for roundKey in product(*candidates):
        masterKey = round2master(list(roundKey))
        plain1 = BlockCipher(masterKey, 4).decrypt(ciphertexts[0])
        plain2 = BlockCipher(masterKey, 4).decrypt(ciphertexts[1])

        if plain2[:-1] == plain1[:-1]:
            print('solved:', masterKey.hex())
            return masterKey


key = integral()
flag_cipher = BlockCipher(key, 20)
flag = b''
for i in range(0, len(enc_flag), 9):
    flag += flag_cipher.decrypt(enc_flag[i:i+9])

print(flag.strip().decode())
