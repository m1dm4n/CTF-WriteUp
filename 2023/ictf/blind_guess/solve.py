from sage.all import *
from pwn import remote, process, args, log as pwnlog
import re
from randcrack import RandCrack
from tqdm import trange


DECK = "🂡🂢🂣🂤🂥🂦🂧🂨🂩🂪🂫🂭🂮"
F = GF(13)  # lucky number
n = 10


def play(io, v, bet, debug=False):
    global DECK
    data = ' '.join(DECK[i] for i in v)
    io.sendlineafter(b"> ", b"play")
    io.sendlineafter(b": ", str(bet).encode())
    io.sendlineafter(b": ", data.encode())
    total = int(re.findall(b"\d+", io.recvuntil(b": "))[0])
    line = io.recvline(0).decode()
    if debug:
        return list(map(DECK.index, line.split())), total, int(io.recvline(0))
    return list(map(DECK.index, line.split())), total


def step1(io):
    global n, F
    I = matrix.identity(n)
    M = []
    for i in range(n):
        Mi = [{j: 0 for j in range(13)} for _ in range(n)]
        for _ in trange(113):
            guess, total = play(io, I[:, i].list(), 1)
            for idx, g in enumerate(guess):
                if g in Mi[idx]:
                    if total == 0:
                        del Mi[idx][g]
                    else:
                        Mi[idx][g] += total
        M.append([max(m.items(), key=lambda ele: ele[1])[0] for m in Mi])
    return matrix(F, M).T


def baby_step(A, v, w, max_ord):
    global n
    m = int(isqrt(max_ord)) + 1
    baby_steps = {}
    baby = matrix.identity(n)
    for i in range(m):
        baby_steps[tuple(baby*v)] = i
        baby = baby * A
    giant_step = (A**m).inverse()
    giant = w
    for i in range(m):
        ans = baby_steps.get(tuple(giant), None)
        if ans is not None:
            return i*m + ans
        giant = giant_step * giant


while True:
    try:
        if args.LOCAL:
            io = process("./main.py", shell=True)
            print(io.recvuntil(b"]]").decode())
        else:
            io = remote("blind-guess.chal.imaginaryctf.org", 1337)
        M = step1(io)
        order = M.multiplicative_order()
        if M.rank() != n or order.nbits() <= 32:
            raise Exception("Nope!")
        print(M)
        print(order, order.nbits())
        v, _ = play(io, [1]*n, 1)
        Rc = RandCrack()
        for i in trange(624, desc='Feeding randcrack'):
            if args.LOCAL:
                w, _, _x = play(io, [1]*n, 1, True)
            else:
                w, _ = play(io, [1]*n, 1)
            x = baby_step(M, vector(F, v), vector(F, w), 2**32)
            if args.LOCAL:
                assert x == _x
            Rc.submit(x)
            v = w
        print("Nice")
        v = vector(F, v)
        while True:
            balance = int(io.recvline(0).split()[-1])
            if balance > 1_000_000_000:
                break
            x = Rc.predict_getrandbits(32)
            v = M**x * v
            v, total = play(io, M.solve_right(v), balance)
            print(balance, total, x)
            v = vector(F, v)
            assert total == n

        io.sendlineafter(b"> ", b"buy flag")
        io.interactive()
        exit(0)
    except Exception:
        io.close()
        continue
 