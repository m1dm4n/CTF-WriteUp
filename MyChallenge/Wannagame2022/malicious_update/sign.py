import glob
import os
import ecdsa
from hashlib import sha256



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
        print(rel_path)
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
        final_hash = xor(final_hash, h.digest())

    return final_hash


a = os.getcwd() + "/module"
h = compute_hash_of_directory(a)
privatekey = open("private.pem",'rb').read()
with open("signature.bin", "wb") as f:
    f.write(ecdsa.SigningKey.from_pem(privatekey).sign_digest(h))
