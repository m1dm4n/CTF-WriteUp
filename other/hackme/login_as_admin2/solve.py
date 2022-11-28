import hashpumpy
import base64
import requests
user = "NmJjYjljOTE1NTk3NWE1M2U5NTFiMGI1MGYxMzc0ODAjbmFtZT1ndWVzdCZhZG1pbj0w"
sig, data = base64.b64decode(user).split(b"#")
print(sig, data)
r = requests.Session()
i = 1
while True:
    print("[+] Length of secret:", i)
    newsig, newdata = hashpumpy.hashpump(sig, data, b"&admin=1", i)
    re = r.get("https://ctf.hackme.quest/login2/", cookies={
        'user': base64.b64encode(newsig.encode() + b"#" + newdata).decode()
    }).text
    if "FLAG{" in re:
        print(re)
        break
    i += 1
