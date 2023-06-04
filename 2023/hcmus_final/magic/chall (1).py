from Crypto.Util.number import bytes_to_long, getPrime
from sympy import nextprime

flag = b'HCMUS-CTF{#####################################}'
e = 0x10001 
m = 16

p = getPrime(1024) 
def generate(p): 
    i = 0 
    while(i<m): 
        i+=1 
        p= nextprime(p+ getPrime(512)) 
    return p 
q = generate(p) 
n = p*q 
c = pow(bytes_to_long(flag),e,n)
print(f"c = ", c)
print(f"n = ", n)
print(f"e = ", e)