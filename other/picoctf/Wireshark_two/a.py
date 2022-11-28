from base64 import b64decode

def check (text:str):
    for c in text:
        if not c.isalnum() and c not in "{}_":
            return False
    return True

with open ("D:\code\ctf\picoctf\\capture.csv", "r") as f:
    file = f.read().replace("\n", ",").replace("\"","").split(",")

flag = ""
for i in file:
    if i.startswith("Standard"):
        tmp = i.split(".reddshrimpandherring")[0].split(" A ")[1]
        try:
            tmp = b64decode(tmp).decode()
        except:
            continue
        if tmp not in flag and check(tmp):
            flag += tmp

print(flag)