from pwn import remote


io = remote("blocky-4.chal.perfect.blue", 1337)

enc = io.recvline(0).decode().split(': ')[-1]

payload = b'a' * 8

f = open('output.txt', 'w')
f.write(enc + '\n')
total = 0
for i in range(0, 243, 27):
    tmp = b''
    for j in range(27):
        tmp += payload + bytes([i + j])
    io.sendlineafter(b'> ', tmp.hex().encode())
    line = io.recvline(0).decode().split(': ')[-1]
    data = [line[i:i + 18] for i in range(0, len(line), 18)]
    for d in data:
        total += 1
        f.write(d + '\n')
    print(total)
f.close()