from pwn import remote, process, log, args, debug, info, log as pwnLog
import time
from sage.all import vector, matrix, ZZ, save, load
import random
from tqdm import trange

def gen_key(user_id, n):
    random.seed(user_id)
    return [random.randrange(1024) for i in range(n)]


def solve(A, B):
    for ans in A.augment(-vector(B)).right_kernel().basis():
        if all(0 <= abs(_) <= 255 for _ in ans[:-1]):
            return bytes(ans[:-1].list())
    return None


# pays = []
# prev_t = None
# while len(pays) < 40:
#     t = time.time()
#     if int(t) == prev_t or (t - int(t)) - 0.3 <= 1e-10 or (t - int(t)) >= 0.6:
#         continue
#     prev_t = int(t)
#     with remote('cry1.chall.ctf.blackpinker.com', 443, ssl=True, level='error') as io:
#     # with remote('0.0.0.0', 1337, level='error') as io:
#         io.recvline(0)
#         b = int(io.recvline(0).split(b': ')[-1])
#         # A.append(a)
#         print(f"start: {t}, end: {time.time()}", b)
#         pays.append((t, b))
# save(pays, 'log')


pays = load('log.sobj')
error = None
for eps in trange(-10, 10):
    A = matrix(ZZ, 26, 26)
    B = []
    r = 0
    time_gen = iter(pays)
    while r < 26:
        t, out = next(time_gen)
        A.set_row(r, gen_key(int(t+eps), 26))
        if A.rank() == r:
            continue 
        B.append(out)
        r += 1
    flag = solve(A, B)
    if flag:
        error = eps
        break
print(error)
print(flag)
# HCMUS-CTF{the_EASIEST_0ne}
