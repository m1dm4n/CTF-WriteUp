import sys
import hashlib

from pwn import *

key = b"0" * 30

with open(sys.argv[1], "rb") as f:
    data = f.read()

# elf hdr
i = 0
elfhdr = data[:0x40]
salt = f"elf{i}00".encode("latin1")
h = hashlib.sha256(salt + key + elfhdr).hexdigest().upper()
print(f"{i}:{h}")

# program headers
i += 1
phoff = u64(elfhdr[0x20 : 0x20+8])
phsize = 56 * u16(elfhdr[0x38 : 0x38+2])
phdrs = data[phoff : phoff + phsize]

salt = f"phdrs{i}00".encode("latin1")
h = hashlib.sha256(salt + key + phdrs).hexdigest().upper()
print(f"{i}:{h}")

# section headers
i += 1

shoff = u64(elfhdr[0x28 : 0x28+8])
shnum = u16(elfhdr[0x3c : 0x3c+2])
shsize = 64 * shnum
shdata = data[shoff : shoff + shsize]

salt = f"shdrs{i}00".encode("latin1")
h = hashlib.sha256(salt + key + shdata).hexdigest().upper()
print(f"{i}:{h}")

# section data
k = 0

while k < shnum:
    shdr = shdata[k*64 : (k+1)*64]
    sec_offset = u64(shdr[0x18: 0x18+8])
    sec_size = u64(shdr[0x20: 0x20+8])
    sec_type = u32(shdr[0x4: 0x4+4])

    if sec_type != 8 and k < shnum - 1:
        next_shdr = shdata[(k+1)*64 : (k+2)*64]
        next_sh_offset = u64(next_shdr[0x18: 0x18+8])
        sec_size = next_sh_offset - sec_offset

    sec_data = data[sec_offset : sec_offset + sec_size]
    i += 1
    salt = "s{}{:02X}".format(i, k).encode("latin1")
    h = hashlib.sha256(salt + key + sec_data).hexdigest().upper()
    print(f"{i}:{h}", k, hex(sec_offset), sec_size, sec_data, sep=' --- ')

    k += 1
