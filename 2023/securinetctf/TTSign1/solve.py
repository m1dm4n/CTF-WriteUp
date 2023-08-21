import hashlib
import re

from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import remote, xor

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
    io.sendlineafter(b"ref", ref.encode())
    io.sendlineafter(b": ", (s.hex() + '|' + params.hex()).encode())
    return io.recvline(0)


def _hash(data):
    return hashlib.sha512(data.encode()).hexdigest()


# Our target
transfer = {
    "ref": "a36eca5c",
    "sender": "Mallory",
    "receiver": "Alice",
    "amount": 337,
    "label": "for charity"
}

io = remote("crypto.securinets.tn", 9898)
init()

# Create a normal transfer
ref1, s1, enc_param = create_transfer("Bob", 1)

param = eval(sign_transfer(ref1, long_to_bytes(2), enc_param))
param = b"\x00\x80" + param

cks = eval(io.recvline(0).split(b" transfer ")[-1])

def _parse_keys(params):
    lp = bytes_to_long(params[:2])
    params = params[2:]
    p = bytes_to_long(params[:lp])
    integrety_check1=params.index(b"U cant fool me")+1
    params = params[integrety_check1+13:]
    lq = bytes_to_long(params[:2])
    params = params[2:]
    q = bytes_to_long(params[:lq])
    integrety_check2=params.index(b"Guess this one")+1
    params =  params[integrety_check2+13:]
    ld = bytes_to_long(params[:2])
    params = params[2:]
    d = bytes_to_long(params[:ld])
    return d, p, q,integrety_check1,integrety_check2


d, p, q, _, _ = _parse_keys(param)
n = p*q
print(d, p, q)
print(f"{cks = }")
enc_param = enc_param[:-16] + xor(enc_param[:16], xor(param[:16], cks)) + enc_param[16:32]
sign_transfer(ref1, long_to_bytes(2), enc_param)
msg = f"ref:{transfer['ref']};from:{transfer['sender']};to:{transfer['receiver']};amount:{str(transfer['amount'])};label:{transfer['label']}"
s = pow(int(_hash(msg), 16), d, n)
sign_transfer(transfer['ref'], long_to_bytes(s), enc_param)
io.sendlineafter(b"> ", b"3")
io.interactive()
