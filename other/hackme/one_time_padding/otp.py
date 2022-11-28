import requests

CharSpace = set(range(256))
SetOfEachEncryptedChar = {i: {} for i in range(50)}
req = requests.Session()
while True:
    r = req.get('https://hackme.inndy.tw/otp/?issue_otp=show')
    cs = r.text.split('\n')

    for i in range(20):
        cs[i] = bytes.fromhex(cs[i])
        assert (len(cs[i]) == 50)

    for i in range(20):
        for j in range(50):
            SetOfEachEncryptedChar[j][cs[i][j]] = 1
    print("[-] Gathering set of each encrypted char")
    print(''.join([f'Flag[{i}]: ' + '%3d; ' %
          len(SetOfEachEncryptedChar[i]) for i in range(50)]))

    counter = 0
    for i in range(50):
        counter += (len(SetOfEachEncryptedChar[i]) == 255)
         
    if counter == 50:
        break

flag = bytearray()

for i in range(50):
    v = list(CharSpace - set(SetOfEachEncryptedChar[i].keys()))
    assert(len(v) == 1)
    flag.append(v[0])

print(f"\n[+] Flag: {flag.decode()}")
