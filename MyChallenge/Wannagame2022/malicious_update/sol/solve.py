import time
from sage.all import matrix, vector, GF, ZZ
from Crypto.Util.number import bytes_to_long as btl
from hashlib import sha256
from os import urandom
import os
import glob
from shutil import make_archive, rmtree


def hash2vec(h):
    return vector(F, list(map(int, bin(btl(h))[2:].zfill(256))))


def xor(bs1: bytearray, bs2: bytearray):
    assert len(bs1) == len(bs2)
    return bytearray([b1 ^ b2 for b1, b2 in zip(bs1, bs2)])


def compute_hash_of_directory(directory: str) -> bytearray:
    """
    Compute a hash of all files contained in <directory>.
    """
    final_hash = bytearray(sha256().digest_size)
    files = glob.glob(directory + "/**", recursive=True)
    files.sort()
    files.remove(directory + '/')
    for path in files:
        rel_path = os.path.relpath(path, directory)
        h = sha256()
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                h.update(rel_path.encode('utf-8'))
                h.update(b"\0")
                h.update(f.read())
        elif os.path.isdir(path):
            h.update((rel_path+'/').encode('utf-8') + b"\0")
        else:
            raise RuntimeError(
                "I don't know what you are doing but i don't like that!"
            )
        print(rel_path, h.hexdigest())
        final_hash = xor(final_hash, h.digest())

    return final_hash


def solve():
    m1 = sha256(path.encode() + b'\0').digest()
    m2 = sha256(shell_name.encode() + b'\0' + shell).digest()
    print(path[:-1], m1.hex())
    print(shell_name, m2.hex())
    mat = [hash2vec(m1), hash2vec(m2)]
    name_datas = []
    while True:
        _mat = mat[:]
        prev_rank = matrix(F, mat).rank()
        name = path + 'z' + f"{prev_rank:02x}"
        data = urandom(10)
        h = hash2vec(sha256(name.encode() + b'\0' + data).digest())
        _mat.append(h)
        cur_rank = matrix(F, _mat).rank()
        if cur_rank == prev_rank:
            continue
        mat.append(h)
        name_datas.append((name, data))
        if cur_rank == 256:
            break
    mat = matrix(F, mat).transpose()
    X = mat.solve_right(target_vec).change_ring(ZZ).list()

    if X[0] != 1 or X[1] != 1:
        print("Try again!")
        return False

    X = X[2:]
    for i, (name, data) in zip(X, name_datas):
        if i:
            with open('app/module/'+name, 'wb') as f:
                f.write(data)
    assert compute_hash_of_directory('./app/module') == target
    return True


F = GF(2)
target = b'sh\xb4\xaftH\xe7@\xf0e\x7f\xe0\x9e\xd6@0\xfc\xabL\xc0<I\x12k\xb1S)\xeb\xea"\xa3N'
target_vec = hash2vec(target)
path = f'shell_{int(time.time())}/'
if os.path.exists('app/module/' + path):
    rmtree('app/module/' + path)

os.mkdir('app/module/' + path)
shell_name = path + 'setup.py'
shell = open('shell.py', 'rb').read()
with open('app/module/'+shell_name, 'wb') as f:
    f.write(shell)

while True:
    if solve():
        break

make_archive(f'test_{int(time.time())}',  'zip', 'app')
rmtree('app/module/' + path)
