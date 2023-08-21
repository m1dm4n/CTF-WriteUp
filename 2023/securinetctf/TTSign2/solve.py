import hashlib
import re

from Crypto.Util.number import long_to_bytes
from gmpy2 import mpz
from pwn import remote
from sage.all import gcd, next_prime
from tqdm import trange


def init(username='Alice', password='IsRSAacommunistscheme'):
    global io
    io.sendlineafter(b": ", username.encode())
    io.sendlineafter(b": ", password.encode())


def create_transfer(to: str, amount: int, label="lmao"):
    global io
    io.sendlineafter(b"> ", str(1).encode())
    io.sendlineafter(b": ", to.encode())
    io.sendlineafter(b": ", str(amount).encode())
    io.sendlineafter(b": ", label.encode())
    line = re.search(
        "Here is your reference: (.*),sign it to finilize transaction here is your signature (.*)",
        io.recvline().strip().decode()
    )
    proof = line.group(2).split("|")
    return (
        line.group(1),
        bytes.fromhex(proof[0]),
        bytearray.fromhex(proof[1]),
    )


def sign_transfer(ref: str, s: bytes, params: bytes):
    global io
    io.sendlineafter(b"> ", str(2).encode())
    io.sendlineafter(b": ", ref.encode())
    io.sendlineafter(b": ", (s.hex() + '|' + params.hex()).encode())
    return io.recvline(0)


def _hash(data):
    return hashlib.sha512(data.encode()).hexdigest()


def recover_N(ref, param):
    global io
    ms = []
    m = mpz(2)
    while True:
        _ = sign_transfer(ref, long_to_bytes(m), param)
        me = int(io.recvline(0).decode().split(' : ')[-1], 16)
        ms.append((m**0x10001 - me))
        if len(ms) >= 2 and gcd(ms).nbits() <= 2048:
            return int(gcd(ms))
        m = next_prime(m)


# Our target
transfer = {
    "ref": "a36eca5c",
    "sender": "Mallory",
    "receiver": "Alice",
    "amount": 337,
    "label": "for charity"
}

while True:
    io = remote("crypto2.securinets.tn", 8000)
    init()

    # Create a normal transfer
    ref1, s1, enc_param = create_transfer("Bob", 1)
    normal_param = enc_param[:]

    # Bit flipping to make len(d) == 2
    start = len(enc_param) - 16 - 16 - 256 - 16 - 2
    enc_param[start] ^= 0x1
    enc_param[start + 1] ^= 0x2

    # Check if out flipping is correct
    cks1 = sign_transfer(ref1, long_to_bytes(2), enc_param)
    if b"Traceback" in cks1:
        print(io.recv(2048).decode())
        io.close()
        continue
    me = int(io.recvline(0).decode().split(' : ')[-1], 16)

    # Recover N
    n = recover_N(ref1, normal_param)
    print(f"{n = }")

    # Recover d
    for _d in trange(1, 2**16):
        if pow(me, _d, n) == 2:
            d = _d
            break
    print(f"{d = }")

    # Forge a signature and get flag
    msg = f"ref:{transfer['ref']};from:{transfer['sender']};to:{transfer['receiver']};amount:{str(transfer['amount'])};label:{transfer['label']}"
    s = pow(int(_hash(msg), 16), d, n)
    sign_transfer(transfer['ref'], long_to_bytes(s), enc_param)
    io.sendlineafter(b"> ", b"3")
    io.interactive()
    break
