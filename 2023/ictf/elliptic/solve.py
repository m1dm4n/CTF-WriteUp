from pwn import process, remote, context, info, gdb, args
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import *
import string
from random import choices
from hashlib import sha1
# context.log_level = 'debug'

alpha = [chr(i) for i in range(32, 127)]
p = 0xfffffffdffffffffffffffffffffffff
K = GF(p)
a = K(0xfffffffdfffffffffffffffffffffffc)
b = K(0xe87579c11079f43dd824993c2cee5ed3)
E = EllipticCurve(K, (a, b))
G = E(0x161ff7528b899b2d0c28607ca52c5b86, 0xcf5ac8395bafeb13c02da292dded7a83)
E.set_order(0xfffffffe0000000075a30d1b9038a115 * 0x01)
order = 0xfffffffe0000000075a30d1b9038a115
F = GF(order)

#################################################
# https://github.com/daedalus/BreakingECDSAwithLLL
def modular_inv(a, b):
    return int(inverse_mod(a, b))


def make_matrix(msgs, sigs, B):
    m = len(msgs)
    print("Using: %d sigs...\n" % m)
    matrix = Matrix(QQ, m + 2, m + 2)

    msgn, rn, sn = [msgs[-1], sigs[-1][0], sigs[-1][1]]
    rnsn_inv = rn * modular_inv(sn, order) % order
    mnsn_inv = msgn * modular_inv(sn, order) % order

    for i in range(0, m):
        matrix[i, i] = order

    for i in range(0, m):
        # r_i/s_i - r_0/s_0
        x0 = (sigs[i][0] * modular_inv(sigs[i][1], order)) - rnsn_inv
        # m_i/s_i - m_0/s_0
        x1 = (msgs[i] * modular_inv(sigs[i][1], order)) - mnsn_inv
        matrix[m+0, i] = x0 % order
        matrix[m+1, i] = x1 % order

    matrix[m, m] = (QQ(2**B) / order)
    matrix[m+1, m+1] = 2**B

    return matrix


def privkeys_from_reduced_matrix(msgs, sigs, matrix, B):
    keys = []
    msgn, rn, sn = [msgs[-1], sigs[-1][0], sigs[-1][1]]
    for row in matrix:
        if row[-2] == 0:
            continue
        keys.append(int(abs(row[-2]*order) / QQ(2**B)) % order)
        potential_nonce_diff = row[0]
        potential_priv = (sn * msgs[0]) - (sigs[0][1] * msgn) 
        potential_priv -= (sigs[0][1] * sn * potential_nonce_diff)
        try:
            potential_priv *= modular_inv((rn * sigs[0][1]) - (sigs[0][0] * sn), order)
            key = potential_priv % order
            if key and key not in keys:
                keys.append(key)
        except Exception as e:
            sys.stderr.write(str(e)+"\n")
            pass
    return keys
#################################################


def recover_pubkey(m, r, s):
    while r < p:
        R = E.lift_x(ZZ(r))
        u1 = ZZ(F(-m) * F(r)**-1)
        u2 = ZZ(F(s) * F(r)**-1)
        yield u1*G + u2*R
        r += order

def sign(msg):
    con.sendlineafter(b'> ', b'1')
    con.sendafter(b':\n', msg)
    con.recvuntil(b'r = ')
    r = int(bytes.fromhex(con.recvline(0).decode())[::-1].hex(), 16)
    con.recvuntil(b's = ')
    s = int(bytes.fromhex(con.recvline(0).decode())[::-1].hex(), 16)
    return r, s


def edit(orig_msg, orig_r, orig_s, msg):
    con.sendlineafter(b'> ', b'2')
    con.sendafter(b'r = ', long_to_bytes(orig_r)[::-1].hex().encode())
    con.sendafter(b's = ', long_to_bytes(orig_s)[::-1].hex().encode())
    con.sendafter(b':\n', orig_msg)
    con.sendafter(b':\n', msg)
    con.recvuntil(b'r = ')
    r = int(bytes.fromhex(con.recvline(0).decode())[::-1].hex(), 16)
    # r = int(con.recvline(), 16)
    con.recvuntil(b's = ')
    s = int(bytes.fromhex(con.recvline(0).decode())[::-1].hex(), 16)
    # s = int(con.recvline(), 16)
    return r, s



def get_payload():
    msg = ''.join(choices(alpha, k=64)).encode()
    r, s = sign(msg)
    r1, s1 = edit(msg, r, (-s) % order, msg)
    return (
        bytes_to_long(sha1(msg).digest()[:16][::-1]),
        r1,
        s1
    )

while True:
    if args.REMOTE:
        con = remote("elliptic.chal.imaginaryctf.org", 1337)
    else:
        con = process('./elliptic')
        if args.GDB:
            gdb.attach(con, gdbscript="""""")
    payload = []
    for i in range(0x12//2):
        payload.append(get_payload())
    # save(payload, "payload")
    pubkey = []
    for sig in payload:
        for Y in recover_pubkey(sig[0], sig[1], sig[2]):
            pubkey.append(Y)
    print(len(pubkey))
    print(len(set(pubkey)))

    msgs = [m for m, _, _ in payload]
    sigs = [(r, s) for _, r, s in payload]
    mat = make_matrix(msgs, sigs, 112)
    keys = privkeys_from_reduced_matrix(msgs, sigs, mat.LLL(), 112)
    priv = None
    for key in keys:
        try:
            if (key*G) in pubkey:
                priv = key
                break
        except Exception:
            pass
    print(priv)

    # get flag
    con.sendlineafter(b"> ", b"3")
    magic = int.from_bytes(bytes.fromhex(con.recvline(0).split()[-1].decode()), 'little')
    k = randint(1, order-1)
    r = int((ZZ(k)*G).xy()[0])
    s = (magic + r*priv) * modular_inv(k, order) % order
    con.sendlineafter(b"= ", long_to_bytes(r)[::-1].hex().encode())
    con.sendlineafter(b"= ", long_to_bytes(s)[::-1].hex().encode())
    con.interactive()
    con.close()