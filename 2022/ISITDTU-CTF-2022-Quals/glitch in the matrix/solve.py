from pwn import remote
from sage.all import matrix, GF, vector, VectorSpace
from Crypto.Util.number import long_to_bytes
F = GF(2)
io = remote('34.132.73.130', 8002)
V = VectorSpace(F, 128)
basis = []

while True:
    io.sendlineafter(b'Your option> ', b'2')
    line = bytes.fromhex(io.recvline().decode().split(': ')[-1])
    M = [b for c in line[:16] for b in map(int, "{:08b}".format(c))]
    _tmp = basis[:]
    _tmp.append(V(M))
    if matrix(F, _tmp).rank() == len(basis):
        continue
    basis.append(V(M))
    print(len(basis))
    if matrix(F, basis).rank() == 64:
        break
print()
basis = V.subspace(basis).basis()

io.sendlineafter(b'Your option> ', b'3')
mat = matrix(F, basis)
print(mat.rank())
io.sendlineafter(b'Your option> ', b'2')
line = bytes.fromhex(io.recvline().decode().split(': ')[-1])
ps = ''
for i in range(0, len(line), 16):
    M = [b for c in line[i:i+16] for b in map(int, "{:08b}".format(c))]
    try:
        s = mat.solve_left(vector(F, M))
        ps += '1'
    except:
        ps += '0'
        pass
print(long_to_bytes((~int(ps, 2)) & 0xffffffffffffffff).hex())
print(long_to_bytes(int(ps, 2)).hex())


io.interactive()
