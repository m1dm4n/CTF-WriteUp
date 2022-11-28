import base64
import requests

def Xor(a, b):
    assert(len(a) == len(b))
    return bytes([ i ^ j for i, j in zip(a, b) ])

auth = b'{"name":"guest","admin":false}'
c = base64.b64decode("U/osUbnY8nSrWz4WPwKSwWPzKq9tOIQ9eCWnN5E+")
key = Xor(auth, c)

new_auth = b'{"name":"admin", "admin":true}'
new_c = Xor(new_auth, key)

r = requests.get('https://hackme.inndy.tw/login5/', cookies={'user5':base64.b64encode(new_c).decode()})
print(r.text)
print(base64.b64encode(new_c).decode())
