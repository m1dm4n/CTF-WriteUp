from pwn import remote, process, log
from const import SEEDLEN
import bitstring
from Crypto.Cipher import AES

def solve():
    # conn = remote("guessq.balsnctf.com", 1258)
    conn = process("./main.py")

    threshold = 0.7

    conn.recvuntil(b"transmitted.]")
    conn.recvline()

    seed = []
    batch_size = 192

    prog = log.progress("Recovering seed")

    for i in range(SEEDLEN // batch_size):
        cnt = 0
        table = [0] * batch_size
        
        for j in range(60):
            prog.status(f"{i} {j}")
            conn.sendline(b"0" * (batch_size * i) + b"1" * batch_size)

            tmp = conn.recvline().decode().strip()

            observed = [int(x) for x in tmp[batch_size * i: batch_size * (i + 1)] ]
            for idx, b in enumerate(observed):
                table[idx] += b
            
            # receive index key str
            index_key = list(map(int, conn.recvline().decode().strip().split(",")))
            conn.recvline()
            line = conn.recvline().decode().strip()

            cnt += 1

            if line.startswith("["):
                # failed
                continue
            else:
                # success
                ct = bytes.fromhex(line)
                # print(conn.recvlines(12))
                nonce = bytes.fromhex(conn.recvline().decode().strip())
                break
        
        for b in table:
            if b / cnt >= threshold:
                seed.append(1)
            else:
                seed.append(0)


    conn.sendline(b"1" * SEEDLEN)
    conn.recvline()
    index_key = list(map(int, conn.recvline().decode().strip().split(",")))
    conn.recvline()
    ct = bytes.fromhex(conn.recvline().decode().strip())
    nonce = bytes.fromhex(conn.recvline().decode().strip())

    key = bitstring.BitArray([seed[i] for i in index_key])[0:256].tobytes()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    pt = cipher.decrypt(ct)

    print(pt)

solve()        








