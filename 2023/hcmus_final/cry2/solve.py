from collections import Counter
from pwn import remote, process, log, args, debug, info, log as pwnLog
from sage.all import matrix, save, load
import random
from numpy.linalg import solve
import numpy as np


def gen_key(user_id):
    random.seed(user_id)
    return [random.randrange(512) for _ in range(32)]


# pays = []
pays = load('log.sobj')

while len(pays) < 200:
    with remote('cry2.chall.ctf.blackpinker.com', 443, ssl=True, level='error') as io:
        # with remote('0.0.0.0', 1337, level='error') as io:
        t = float(io.recvline(0).split(b': ')[-1])
        b = int(io.recvline(0).split(b': ')[-1])
        # A.append(a)
        print(f"time: {t},", b)
        pays.append((t, b))
save(pays, 'log')


keys = [gen_key(t) for t, _ in pays]
anss = [b for _, b in pays]

C = [Counter() for i in range(31)]
while True:
    A = random.sample(keys, k=32)
    if matrix(A).rank() != 32:
        continue
    b = [anss[keys.index(a)] for a in A]
    flag = solve(np.array(A), np.array(b))
    if abs(flag[-1]) > 2:
        continue
    flag = flag[:-1].round().astype(int).tolist()
    for idx, f in enumerate(flag):
        C[idx][f] += 1
    print(bytes([c.most_common(1)[0][0] for c in C]))
