import subprocess
import tempfile
import glob
import os
import ecdsa
import zipfile
from hashlib import sha256

size_limit = 1 << 20
public_key = open('public.pem', 'rb').read()
timeout = 10


def check_size(file_list: list) -> bool:
    total = 0
    for file in file_list:
        total += file.file_size
        if total >= size_limit:
            return False
    return True


def xor(bs1: bytearray, bs2: bytearray):
    assert len(bs1) == len(bs2)
    return bytearray([b1 ^ b2 for b1, b2 in zip(bs1, bs2)])


def unpack_zip_file_to_dir(path_to_zip_file: str, unpack_dir: str):
    with zipfile.ZipFile(path_to_zip_file) as z:
        z.extractall(unpack_dir)


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


def verify_module_signature(
    path_to_module: str,
    signature_filename: str = "signature.bin"
) -> bool:
    path_to_verify = path_to_module + "/module"
    path_to_signature = path_to_module + "/" + signature_filename
    if not os.path.isdir(path_to_verify):
        return False
    if not os.path.isfile(path_to_signature):
        return False

    hash_value = compute_hash_of_directory(path_to_verify)
    with open(path_to_signature, "rb") as f:
        signature = f.read()
    print(signature)
    print(hash_value)
    vk = ecdsa.VerifyingKey.from_pem(
        public_key, hashfunc=sha256
    )
    return vk.verify_digest(signature, hash_value, allow_truncate=True)


def do_install(module_path: str):
    modules = glob.glob(module_path + "/**")
    modules.sort()
    for module in modules:
        if not os.path.isdir(module) or not os.path.exists(f'{module}/setup.py'):
            continue
        subprocess.run(
            ['python3', f'{module}/setup.py', 'install'],
            cwd=module_path,
            timeout=timeout,
            check=True
        )

def verify_and_install(path_to_zip_file: str):
    with zipfile.ZipFile(path_to_zip_file) as f:
        if not check_size(f.infolist()):
            raise RuntimeError(
                RuntimeError(
                    "Uncompressed zip file would be too large.\n"
                    "Allowed size ({}) exceeded at file {}".format(
                        size_limit,
                        f.filename
                    )
                )
            )
    with tempfile.TemporaryDirectory(prefix="module_update_") as work_dir:
        unpack_zip_file_to_dir(path_to_zip_file, work_dir)
        valid = verify_module_signature(work_dir)
        if not valid:
            raise RuntimeError("Error when verifying signature!")
        else:
            do_install(work_dir + '/module')
