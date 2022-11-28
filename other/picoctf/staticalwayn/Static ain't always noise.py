with open ('D:\code\ctf\picoctf\staticalwayn\static', 'rb') as f:
    bin = f.read()
a = ""
for i in bin:
    if chr(i).isprintable() :
        a += chr(i)
print(a[a.index("pico"): a.index("}", (a.index("pico")))+1])