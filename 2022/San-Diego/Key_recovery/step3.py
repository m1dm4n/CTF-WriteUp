import base64

with open("newkey") as pk:
    lines = list(pk)
    b64 = ''.join((line[:-1] for line in lines[1:-1]))
    bys1 = bytearray(base64.b64decode(b64))


with open("id_rsa.corrupted") as pk:
    lines = list(pk)
    b64 = ''.join((line[:-1] for line in lines[1:-1]))
    bys2 = bytearray(base64.b64decode(b64))


OFFSET_LENGTHS = [(454 + 808, 190), (454 + 1004, 193), (454 + 1201, 193)]

for offset, length in OFFSET_LENGTHS:
    bys2[offset:offset+length] = bys1[offset:offset+length]


HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----\n'
FOOTER = '-----END OPENSSH PRIVATE KEY-----\n'
LINE_LENGTH = 70  # Excluding newline characters


corrupted_b64 = base64.b64encode(bys2).decode('ascii')
with open("id_rsa", 'w') as pk:
    pk.write(HEADER)
    pk.writelines(corrupted_b64[i:i+LINE_LENGTH] + '\n' for i in range(0, len(corrupted_b64), LINE_LENGTH))
    pk.write(FOOTER)
