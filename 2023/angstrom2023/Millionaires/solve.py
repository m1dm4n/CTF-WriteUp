
import private_set_intersection.python as psi
from pwn import remote, process, log, args
from base64 import b64encode, b64decode


const = set()
const.add('0')
const.add('1')
for i in range(7):
    tmp = list(const)
    for j in tmp:
        const.add(j + '1')
        const.add(j + '0')
tmp = sorted(list(const), key=lambda _: len(_))
const = []
for i in tmp:
    if i[-1] == '1':
        const.append(i)
print(len(const))


def solve():
    state = ""
    start = True
    cnt = 0
    c = psi.client.CreateWithNewKey(True)
    setup = psi.ServerSetup()
    resp = psi.Response()
    # with log.progress("Finding secret") as LOG:
    while True:
        cnt += 1
        # LOG.status(state)
        # client_set = fill(state)
        client_set = [state + i for i in const]
        io.sendlineafter(b': ', str(len(const)).encode())

        msg = io.recvline(0).split(b':')[-1].strip()

        setup.ParseFromString(b64decode(msg))

        req = b64encode(c.CreateRequest(client_set).SerializeToString())
        io.sendlineafter(b':', req)

        resp.ParseFromString(b64decode(io.recvline(0).strip()))
        intersection = sorted(c.GetIntersection(setup, resp))
        io.sendlineafter(b': ', b'')
        if len(intersection) == 0:
            # LOG.success(state)
            io.sendlineafter(b'? ', b'y')
            state = state.ljust(256, '0')
            return cnt, int(state, 2)

        state = client_set[intersection[-1]]
        if not start:
            io.sendlineafter(b'? ', b'n')
        start = False


def fake_psi(a, b):
    return [i for i in a if i in b]


def zero_encoding(x, n):
    ret = []

    s = bin(x)[2:].zfill(n)

    for i in range(n):
        if s[i] == "0":
            ret.append(s[:i] + "1")

    return ret


def one_encoding(x, n):
    ret = []
    s = bin(x)[2:].zfill(n)
    for i in range(n):
        if s[i] == "1":
            ret.append(s[:i+1])
    return ret


def pass_check(num):
    c = 0
    while True:
        tmp = sorted(fake_psi(one_encoding(num, 256),
                     zero_encoding(c, 256)), key=lambda _: len(_))
        print(tmp)
        if tmp == []:
            return c
        c += 1


while True:
    try:
        if args.LOCAL:
            io = process(['python', 'millionaires.py'])
        else:
            io = remote('challs.actf.co', 32300)
        if not args.LOCAL:
            import os
            io.recvuntil(b': ')
            cmd = io.recvline(0).decode()
            assert os.system(cmd + ' > pow.txt') == 0, 'PoW failed!'
            PoW = open('pow.txt', 'rb').read().strip()
            io.sendlineafter(b': ', PoW)
        for i in range(10):
            # io.recvline()
            # print(io.recvline())
            cnt, secret = solve()
            print(secret)
            io.sendlineafter(b': ', str(secret).encode())
            x = int('1'*256, 2)
            # print(zero_encoding(x, 256))
            for j in range(cnt):
                io.sendlineafter(b': ', str(x).encode())
    except Exception:
        io.close()
        continue
    io.interactive()
    break