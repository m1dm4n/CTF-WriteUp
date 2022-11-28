from base64 import *
import requests

BIT = ord('0') ^ ord('1')

def bit_flip(idx:int, data:str) -> str:
    raw = b64decode(b64decode(data))
    arr = bytearray(raw)
    arr[idx] = arr[idx] ^ BIT
    return b64encode(b64encode(bytes(arr))).decode()

def main():
    session = requests.Session()
    session.get('http://mercury.picoctf.net:15614/')
    cookie = session.cookies.get_dict()
    cbc = cookie["auth_name"]
    print(f'Origin cookie: {cbc}')
    for idx in range(96): 
        print(f'+ Flipping bit at index {idx}...')
        cookie = {'auth_name': bit_flip(idx, cbc)}
        t = requests.get('http://mercury.picoctf.net:15614/', cookies=cookie)
        if "picoCTF{" in t.text:
            print("""
            ********************************************************************
            *                          Successful!!!                           *
            *                                                                  *
            ********************************************************************
            """)
            print("Changed cookie :", {cookie['auth_name']}, "\n")
            html = t.text
            begin = html.index("picoCTF{")
            end = html.index("}", begin) + 1
            print("Flag:", html[begin:end])
            break

main()         
#picoCTF{cO0ki3s_yum_a9a19fa6} 