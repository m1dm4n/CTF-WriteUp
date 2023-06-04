import numpy as np
import os
import pickle

FLAG = os.getenv('FLAG', "FLAG{this is a real flag}")
assert len(FLAG) < 50
FLAG_A = np.array([ord(b) for b in FLAG])


def encrypt(message: np.ndarray = FLAG_A):
    ct = np.zeros(169, dtype=int)
    while ct[0] == 0:
        k = np.random.choice(range(-5, 5), size=(120,))

        np.random.shuffle(k)
        pt = np.random.choice(range(32, 128), size=(288, ))
        l = len(message)
        s = np.random.randint(119, 169-l)
        pt[:119] = np.zeros(119, dtype=int)
        pt[-119:] = pt[:119]

        pt[s:s+len(message)] = message
        for i in range(169):
            ct[i] = np.sum(k[::-1] * pt[i:i+120])

    return ct, k


ct, k = encrypt()
with open('ciphertext_and_key.bin', 'wb') as file:
    pickle.Pickler(file, protocol=pickle.HIGHEST_PROTOCOL).dump((ct, k))
