ct = eval(open("./public/leaked_traces/ciphertext.json", "rb").read())
ft = eval(open("./public/leaked_traces/faulty_ciphertext.json", "rb").read())
pt = eval(open("./public/leaked_traces/plaintext.json", "rb").read())
print(bytes(pt[0]).hex() + ',' + bytes(ct[0]).hex())
for i in range(1, len(ct)):
    print(bytes(ct[i]).hex() + ',' + bytes(ft[i]).hex())