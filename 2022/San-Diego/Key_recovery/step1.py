import sys
import base64
import struct
# ssh-keygen -y -f id_rsa.corrupted > key.pub
# get the second field from the public key file.
keydata = base64.b64decode(
    open('key.pub').read().split(None)[1])

parts = []
while keydata:
    # read the length of the data
    l = struct.unpack('>I', keydata[:4])[0]

    data, keydata = keydata[4:l+4], keydata[4+l:]

    parts.append(data)
print(parts)
e_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', bytes([x]))[0] for x in parts[1]]))
n_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', bytes([x]))[0] for x in parts[2]]))


print(e_val)
print(n_val)
