# Key Recovery - Crypto 250 - 39 solves

![image](https://user-images.githubusercontent.com/92845822/167410209-c5f6a18c-c9ea-4812-9273-5092fb48cfca.png)

Challenge này cung cấp 1 file OpenSSH private key bị xóa đi các bytes và ta cần phải phục hồi lại nguyên trạng ban đầu. 

![image](https://user-images.githubusercontent.com/92845822/167399716-e59e7a95-e7b8-49f1-be85-9cb0cd7f7c9e.png)

Sau khi decode toàn bộ base64 ra thì mình thấy đây là 1 file rsa key. Đây là link mình tham khảo để giải đươc câu này: [OpenSSH format](https://coolaj86.com/articles/openssh-vs-openssl-key-formats/)

Format của 1 file RSA private key: 

![image](https://user-images.githubusercontent.com/92845822/167376189-7c72b22b-638f-4e7d-9ccd-a0e98ac31306.png)

## Phân tích file ransomware.py

 ```python
 #! /usr/bin/env python3
import base64

KEY = 'id_rsa'
COR = 'id_rsa.corrupted'

with open(KEY) as pk:
    lines = list(pk)
    b64 = ''.join((line[:-1] for line in lines[1:-1]))
    bys = bytearray(base64.b64decode(b64))

# Nuke some byte ranges

OFFSET_LENGTHS = [(454 + 808, 190), (454 + 1004, 193), (454 + 1201, 193)] # Specific to this type of key, may not work for others...

for offset, length in OFFSET_LENGTHS:
    bys[offset:offset+length] = b'\0' * length

# Write out the key in the same format as the input key

HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----\n'
FOOTER = '-----END OPENSSH PRIVATE KEY-----\n'
LINE_LENGTH = 70 # Excluding newline characters

corrupted_b64 = base64.b64encode(bys).decode('ascii')

with open(COR, 'w') as pk:
    pk.write(HEADER)
    pk.writelines(corrupted_b64[i:i+LINE_LENGTH] + '\n' for i in range(0, len(corrupted_b64), LINE_LENGTH))
    pk.write(FOOTER)

# Edit: MALICIOUS code commented out BELOW for your safety!
# __import__('os').remove(KEY)

print(f'***** WARNING: YOUR SSH PRIVATE KEY HAS BEEN CORRUPTED *****')
print(f'Pay me 1000 BTC to recover your corrupted private key at {COR}')
 ```
Sau khi đọc file ransom thì thấy các byte từ 1262-1452, 1458-1651, 1655-1848 bị thay bằng **NULL** . Đó có vẻ là các bytes của private key, tuy nhiên các bytes của public key nằm ở đầu nên ta có thể phục hồi được.

## Lấy các giá trị sử dụng được từ file OpenSSH PRIVATE KEY
Sử dụng lệnh ssh-keygen để lấy public key dưới dạng SSH:
> ssh-keygen -y -f id_rsa.corrupted > key.pub

![image](https://user-images.githubusercontent.com/92845822/167352018-603e044e-cf01-4673-9e09-3e645d0e0817.png)

Tới đây mình dùng python để lấy giá trị **n** và **e** từ public key. File [step1](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/step1.py)

```python
import sys
import base64
import struct
# ssh-keygen -y -f id_rsa.corrupted > key.pub
# get the second field from the public key file.
keydata = base64.b64decode(
    open('key.pub').read().split(None)[1])

parts = []
while keydata:
    # read the length of the data
    l = struct.unpack('>I', keydata[:4])[0]

    data, keydata = keydata[4:l+4], keydata[4+l:]

    parts.append(data)
print(parts)
e_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', bytes([x]))[0] for x in parts[1]]))
n_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', bytes([x]))[0] for x in parts[2]]))

print(e_val)
print(n_val)
```

![image](https://user-images.githubusercontent.com/92845822/167362784-1253bd9a-7d42-417c-bcbb-5793cac52e6c.png)

Bây giờ đã có giá trị **n** nên việc đầu tiên mình làm đó là quăng vô [factordb](factordb.com) để kiểm tra xem đã bị leak các giá trị factor chưa. 

![image](https://user-images.githubusercontent.com/92845822/167366296-29dd2610-f029-45c6-a133-583994b9e993.png)

Và thật bất ngờ là nó có thiệt :). Có **p**, **q** rồi ta có thể tìm **phiN** từ đó tính **d**. Như vậy việc cần làm là tìm cách tạo được 1 file private key từ **n, e, d**


## Phục hồi file ban đầu
Sau khi tra Google một hồi mình không tìm ra cách dùng các giá trị của khóa để tạo thành file OpenSSH private key nhưng sau khi đọc 1 bài trên stackoverflow ([link](https://stackoverflow.com/questions/54994641/openssh-private-key-to-rsa-private-key)) thì mình tìm thấy 1 tool là [putty](https://github.com/github/putty) có thể convert được nên mình bật ubuntu chạy thử.

![image](https://user-images.githubusercontent.com/92845822/167402050-aae828c2-5093-4756-9fe6-771883a5751f.png)

Sử dụng thư viện PyCryptodome để tạo 1 file PEM từ các giá trị khóa. 

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
n = 5160506883782749616132783578676599737578181750862768189533614818450602210629498054577038706877878591461730975523298347363175809269708590576234053680856190531462016049228664524032245630383570864862594528039304198008516406311503234891848472500677235233306353194822807809226747910258650946427684458449678036010148784936158504973297476213297246992333561058386122648007679022132436712737675349659381843139241424768652685748923787146445880090032877364507196680645491851110761225396699447973935528224071347899180813330462539836529892009545804429224998924081820947865509113139516184975975194402615711301223800470960317508112510398414265245430205305656570750598921943681519089652640029328107852739267177564249991034151531241398709715045120413280018614249373651221817769351920991448859276737358186725656225666533699293442886175394481957179750678824007967261562704869503123637677559148438013660238339484372216476981537246533669889453857
p = 2239102666933135561942199225708085018160481780967034043147173047566147839050050738202428315348958522434264115740745667710189513247094196395750632928574653735378028005561278278302038978641694242277350257427678723520067491316314717666202751730495393103266518360996211384098928951906037855023727142231156286566083489482555221641491792832584115123420535751875053864863400361980329030505560413787641522985318765990149397031003492064905853575121122602512739897993727029
q = 2304720975948376863359610286058391363543268995439609172215661899731700376813775204230297106360450320802501976838081201590579942180067889742222688077008414263691552744984726414092635334119541091641830599189755142061897046040736060543164061630311637326841024045175364439686677871532139068178542223943598854738781925353561709503743701960412785035904083638325749823108093723759162117295626415249606225750633917328179020525462879693481494374226894054438335455724371133
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)


def test(n, e, d):
    text = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    p = bytes_to_long(text)
    ct = pow(p, e, n)
    pt = pow(ct, d, n)
    return pt == p


assert test(n, e, d)

key = RSA.construct([n, e, d])
with open("key.pem", "wb") as f:
    f.write(key.export_key('PEM'))
```

Chạy file [step2](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/step2.py) để tạo ra 1 file [key.pem](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/key.pem) dạng PEM rồi chạy lệnh bên dưới để chuyển đổi sang file OpenSSH private key (-**C** để thêm comment 'SDCTF' vào file).
>puttygen -C SDCTF key.pem -O private-openssh-new -o newkey

![image](https://user-images.githubusercontent.com/92845822/167403631-4afbb923-bae4-4af0-bba3-6886c953cb23.png)

Mặc dù file bị corupted rất giống file này tuy nhiên ta cần nhớ lại format file

![image](https://user-images.githubusercontent.com/92845822/167411130-d1eb2b5d-9452-4106-9a12-eb1f62959329.png)

So sánh các bytes không bị ảnh hưởng của file [id_rsa.corrupted](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/id_rsa.corrupted) với file vừa có được ta cũng thấy có 8 bytes khác nhau

![image](https://user-images.githubusercontent.com/92845822/167412575-9122882d-00bd-4888-b284-175e894a5b61.png)

Nên lúc này mình sẽ sao chép các bytes của file [id_rsa.corrupted](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/id_rsa.corrupted) và chỉ lấy các bytes bị mất từ file [newkey](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/newkey) rồi chép vào 1 file mới sử dụng bằng đoạn code của file [ransomware.py](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/ransomware.py)

```python
import base64

with open("newkey") as pk:
    lines = list(pk)
    b64 = ''.join((line[:-1] for line in lines[1:-1]))
    bys1 = bytearray(base64.b64decode(b64))


with open("id_rsa.corrupted") as pk:
    lines = list(pk)
    b64 = ''.join((line[:-1] for line in lines[1:-1]))
    bys2 = bytearray(base64.b64decode(b64))


OFFSET_LENGTHS = [(454 + 808, 190), (454 + 1004, 193), (454 + 1201, 193)]

for offset, length in OFFSET_LENGTHS:
    bys2[offset:offset+length] = bys1[offset:offset+length]


HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----\n'
FOOTER = '-----END OPENSSH PRIVATE KEY-----\n'
LINE_LENGTH = 70  # Excluding newline characters


corrupted_b64 = base64.b64encode(bys2).decode('ascii')
with open("id_rsa", 'w') as pk:
    pk.write(HEADER)
    pk.writelines(corrupted_b64[i:i+LINE_LENGTH] + '\n' for i in range(0, len(corrupted_b64), LINE_LENGTH))
    pk.write(FOOTER)
```

Băm nó ra thành sha256 rồi submit là xong.

![image](https://user-images.githubusercontent.com/92845822/167402924-898b712d-5b84-43af-9286-997973ad32a8.png)

File phục hồi hoàn chỉnh: [id_rsa](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/id_rsa)