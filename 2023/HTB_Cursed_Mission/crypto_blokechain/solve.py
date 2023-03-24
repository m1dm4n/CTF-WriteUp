import re
from pwn import process, remote
from collections import Counter


def test(x, clause):
    ans = 1
    for idx, bit in clause:
        ans &= int(x[idx] == bit)
    return ans


def custom_eval(x, clauses):
    ans = 0
    for clause in clauses:
        ans |= test(x, clause)
    return ans


def re_test(pays, samples, real_anss):
    c_max = -1
    if len(pays) == 3:
        pays.append(pays[0])
        permut = [(0, 1, 2, 3), (0, 2, 1, 3)]
    else:
        permut = [(0, 1, 2, 3), (0, 2, 1, 3), (0, 3, 1, 2)]
    ret = None
    for s in permut:
        cl1 = (pays[s[0]], pays[s[1]])
        cl2 = (pays[s[2]], pays[s[3]])
        c = 0
        for sample, real_ans in zip(samples, real_anss):
            ans = custom_eval(sample, (cl1, cl2))
            if ans == real_ans:
                c += 1
        if c > c_max:
            ret = (cl1, cl2)
            c_max = c
    return ret


def get_funcs_of_priv_hash(samples, real_anss):
    equal_1 = []
    for i in range(len(samples)):
        if real_anss[i] == 1:
            equal_1.append(samples[i])
    n1 = len(equal_1)

    clauses = []
    for i in range(50):
        cur = [equal_1[_][i] for _ in range(n1)]
        bit, c = Counter(cur).most_common(1)[0]
        if c/n1 > 0.6:
            clauses.append((i, bit, c/n1))

    clauses = sorted(clauses, key=lambda e: e[2])
    # print(clauses)
    if len(clauses) > 2:
        clauses = [(a[0], a[1]) for a in clauses]
        clauses = re_test(clauses, equal_1, [1] * n1)
    else:
        clauses = [[(a[0], a[1]) for a in clauses]]
    # print(clauses)
    # print()
    return clauses


def get_payload():
    io.sendline(b"1")
    io.sendlineafter(b"vessels\n", b"2")
    io.sendline(suss_nums)
    lines = io.recvuntil(b'vessels\n')
    lines = lines[lines.index(b"expected"):]
    hs = []
    blocks = []
    for line in lines.splitlines()[:-5]:
        nums = re.findall(b" [a-f\d]+", line)
        hs.append(int(nums[0].strip(), 16))
        blocks.append(list(map(int, f"{int(nums[-2].strip()):050b}")))
    io.sendline(b"2")
    io.sendline(b'\n'.join(str(h).encode() for h in ([0] * (60-len(hs)) + hs) ))
    io.recvuntil(b'vessels\n')
    return blocks, hs


def custom_hash(num, funcs):
    numb_bits = list(map(int, f"{num:050b}"))
    res = 0
    for i in range(100):
        res *= 2
        res += custom_eval(numb_bits, funcs[i])
    return res


# io = remote(*("68.183.45.143:32297".split(':')), level='error') # change this if you spawn a new docker
io = process(['python', 'server.py'])
io.recvuntil(b'vessels\n')
print('Start')
suss_nums = b'\n'.join(b'1' for _ in range(60))

server_values = [[] for i in range(100)]
samples = []

while len(samples) < 1111:
    nums, hash_values = get_payload()
    samples.extend(nums)
    for h in hash_values:
        for i in range(99, -1, -1):
            server_values[99-i].append(1 if (h & (2**i)) else 0)


funcs = [get_funcs_of_priv_hash(samples, server_values[i]) for i in range(100)]
print('Successfully guessing some clause from server\'s Private hash!')

while True:
    io.sendline(b"1")
    io.sendlineafter(b"vessels\n", b"2")
    for i in range(60):
        l = io.recvuntil(b': ')
        a = int(re.findall(b"[\d]+", l)[0])
        io.sendline(str(custom_hash(a, funcs)).encode())
    ret = io.recvuntil(b'vessels\n')
    bal_idx = ret.index(b"Balance")
    ret = ret[bal_idx:]
    balance = int(ret.splitlines()[0].split(b': ')[-1])
    print(balance)
    if balance > 100000000:
        break

io.sendline(b"3")
io.interactive()