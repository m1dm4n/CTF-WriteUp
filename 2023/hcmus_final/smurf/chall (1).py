from Crypto.Util.number import bytes_to_long, getPrime

# flag is not too large :D 
flag = b"HCMUS-CTF{?????????????????????}"

plt = bytes_to_long(flag)

e = 11
N = [] 
C = []
for i in range(10): 
    p = getPrime(512) 
    q = getPrime(512) 
    n = p*q 
    c = pow(plt-(i+1),e,n) 
    N.append(n) 
    C.append(c) 
print(f"N = {N}")
print(f"C = {C}")