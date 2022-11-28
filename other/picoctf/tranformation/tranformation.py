
tmp ='灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弲㘶㠴挲ぽ'
for i in range(len(tmp)):
    a = ord(tmp[i]) >> 8
    b = ord(tmp[i]) ^ (a<<8)
    print(chr(a)+chr(b), end='')
