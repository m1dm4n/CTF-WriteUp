from pwn import remote, process


# io = remote("blocky-5.chal.perfect.blue", 1337)
io = process(['python', 'task.py'])
enc = io.recvline(0).decode().split(': ')[-1]


f = open('input.txt', 'w')
for k in range(5):
    prefix = b'\0' * k
    postfix = b'\0' * (8 - k)
    payloads = [prefix + bytes([i]) + postfix for i in range(243)]
    data = b''
    for i in range(0, 2):
        tmp = b''.join(payloads[125*i:125*i + 125])
        io.sendlineafter(b'> ', tmp.hex().encode())
        line = bytes.fromhex(io.recvline(0).decode().split(': ')[-1])
        data += line
    print(len(data))
    data = [data[i:i + 9] for i in range(0, len(data), 9)]
    # print(data)
    for d in data:
        for b in d:
            f.write(str(b) + ' ')
        f.write('\n')

f.close()
f = open('enc_flag.txt', 'w')
f.write(enc + '\n')
f.close()
