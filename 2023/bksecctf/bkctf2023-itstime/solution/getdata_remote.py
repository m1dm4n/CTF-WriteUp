import sys
import os
import numpy as np
import random
from sage.all_cmdline import *
import json
import string
import itertools
import math
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from pwn import remote, process, args, debug, info, log as pwnLog
from tqdm import tqdm, trange
from functools import reduce, cache
from base64 import b64encode, b64decode
from collections import Counter


io = remote("18.141.236.82", 31625)
io.sendlineafter(b"> ", b"2")
io.recvline()
io.recvline()
io.recvline()
ct = io.recvline().decode().split(" = ")[-1]

def parse(bs):
    a = int.from_bytes(bs, 'little')
    ret = []
    for i in range(4):
        ret.append(a % 2**32)
        a >>= 32
    return ret
data = []

io.sendlineafter(b"> ", b"1")
while len(data) < 624:
    print(len(data))
    io.sendlineafter(b"(y/not y) ", b"y")
    for i in range(3):
        k = bytes.fromhex(io.recvline(0).decode().split(' = ')[-1])
        for j in parse(k):
            data.append(j)
            if len(data) == 624:
                print(f"{data = }")
                print(f"{ct = }")
                exit()
    io.recvline()
