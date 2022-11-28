from pwn import remote, process, args
from sage.all import ZZ

HOST = "2022.ductf.dev"
N_BITS = 384


def attack(N, oracles):
    left = ZZ(0)
    right = ZZ(N)
    for i in oracles:
        if i == -1:
            right = (right + left) / 2
        else:
            left = (right + left) / 2
    return int(right)//2


def set_interval(lower, upper):
    io.sendlineafter(b"> ", b'1')
    io.sendlineafter(b'Lower bound: ', str(lower).encode('utf-8'))
    io.sendlineafter(b'Upper bound: ', str(upper).encode('utf-8'))


def get_queries(c):
    io.sendlineafter(b"> ", b'2')
    l = [c * pow(2**i, e, N) for i in range(1, 385)]
    assert len(l) == 384
    payload = ','.join(map(str, l))
    io.sendlineafter(b'queries: ', payload.encode('utf-8'))
    return [int(c.strip()) for c in io.recvline().decode('utf-8').split(',')]


flags = []
for port in [30008, 30011, 30010]:
    if args.DEBUG:
        io = remote(HOST, port, level="debug")
    else:
        io = remote(HOST, port)
    N = int(io.recvline())
    c = int(io.recvline())
    e = 0x10001
    LOWER = N//2
    UPPERR = N
    set_interval(LOWER, UPPERR)
    ora = get_queries(c)
    print(ora)
    s = attack(N, ora)
    print(s)
    io.sendlineafter(b"> ", b'3')
    io.sendlineafter(b'Enter secret: ', str(s).encode('utf-8'))
    flags.append(io.recvline().strip())
    io.close()


for i, flag in enumerate(flags):
    print(f'FLAG{i+1}: {flag.decode("utf-8")}')
