key = 0x87
flag = [0xCB,0xC6,0xC0,0xFC,0xC9,0xE8,0xAB,0xA7,0xDE,0xE8,0xF2,0xA7,0xF4,0xEF,0xE8,0xF2,0xEB,0xE3,0xA7,0xE9,0xE8,0xF3,0xA7,0xF7,0xE6,0xF4,0xF4,0xA7,0xF3,0xEF,0xE2,0xA7,0xE1,0xEB,0xE6,0xE0,0xFA ]  

for c in flag:
    print(chr(c^key), end="")