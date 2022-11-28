import hashlib
from cryptography.fernet import Fernet

key = hashlib.sha256(b"GOUGH").hexdigest()
tmp = [4,5,3,6,2,7,1,8]

print ("picoCTF{1n_7h3_|<3y_of_" + ''.join(key[i] for i in tmp) + '}')
