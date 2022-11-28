from pwn import remote, process, args, log
import re


def n_same(aa, bb):
    c = 0
    for a, b in zip(aa, bb):
        if a == b:
            c += 1
    return c


def count_bits(a):
    c = 0
    b = a
    while b:
        c += (b & 1)
        b >>= 1
    return c


# Get payloads
if args.LOCAL:
    io = process(["./hmac"])
else:
    io = remote("ddt.flu.xxx", 10201)
MAX_PAYLOAD = 100
payloads = []
pts = []
# cts = []
proc = log.progress("Trying byte")
for c in range(MAX_PAYLOAD):
    io.sendlineafter(b"exit\n> ", b'1')
    io.sendlineafter(b"chars: ", bytes([c]).hex().encode())
    lines = io.recvuntil(b"=====================\n").decode().splitlines()[:-1]
    _times = []
    _pt = list(bytes.fromhex(lines[0].split('is now ')[-1]))
    for line in lines[1:-1]:
        _times.append(int(re.findall(r"\d+", line)[0]))
    hash_type = []
    for i in range(1, len(_times)):
        hash_type.append((_times[i] - _times[i-1]) < 100000)

    proc.status(str(c))
    # print(_pt)
    # print(_ct)
    # print(hash_type)
    payloads.append(hash_type)
    pts.append(_pt)
    # _ct = list(bytes.fromhex(lines[-1].split(': ')[-1]))
    # cts.append(_ct)
proc.success(f"\nGot enough {MAX_PAYLOAD} payloads.\n")


# Finding Key
key = []
for i in range(16):
    _base = []
    rk = -1
    M = -1
    for p in payloads:
        _base.append(p[i])
    for k in range(256):
        _check = []
        for j in range(MAX_PAYLOAD):
            _check.append(count_bits(k ^ pts[j][i]) >= 4)
        _tmp = n_same(_check, _base)
        if _tmp > M:
            M = _tmp
            rk = k
    key.append(rk)
    log.info(f"Good byte for index {i}: {rk} ({(M/MAX_PAYLOAD)*100}%)")
log.success("Found session Key: " + bytes(key).hex())


# Get flag
io.sendlineafter(b"exit\n> ", b'2')
io.sendlineafter(b"chars: ", bytes(key).hex().encode())
log.success("FLAG: " + io.recvline().decode())
io.close()