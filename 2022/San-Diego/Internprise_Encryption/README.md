# Internprise Encryption - Revenge 200 - 48 solves
![image](https://user-images.githubusercontent.com/92845822/167444952-347ecaa6-6e0b-47ba-8e63-1ef9ee7252f9.png)

Challenge này ta sẽ được cung câp 1 file zip chứa các file bị mã hóa và hàm mã hóa được viết bằng **javascript**

```javascript showLineNumbers
function encrypt(s) {
    let encrypted = []
    for (let i = 0; i < s.length; i++) {
        let x = (s[i].charCodeAt(0x0) + i * 0xf) % 0x80
        x += i > 0x0 ? encrypted[i - 0x1].charCodeAt(0) % 128 : 0xd
        x ^= 0x555
        x = ((x ^ ~0x0) >>> 0x0) & 0xff
        x -= (Math.random() * 0x5) & 0xb9 & 0x46
        x = ~(x ^ (0x2cd + ((i ^ 0x44) % 0x2 === 0) ? 0x3 : 0x0))
        x = ((x >> 0x1f) + x) ^ (x >> 0x1f)
        x |= ((Date.now() % 0x3e8) / (0x4d2 - 0xea)) | i % 0x1
        encrypted.push(String.fromCharCode(x))
    }
    return encrypted.join("")
}
```

Xong khi chạy thử 1 vài dòng thì mình thấy hàm này có các dòng dư thừa sau:
1.  `(Math.random() * 0x5) & 0xb9 & 0x46`: 0xb9 & 0x46 sẽ ra 0 nên dòng này luôn ra 0
2.  Đoạn code `0x2cd + ((i ^ 0x44) % 0x2 === 0)` này sẽ luôn trả 1 hoặc 0 do đó `(0x2cd + ((i ^ 0x44) % 0x2 === 0) ? 0x3 : 0x0)` sẽ luôn ra `0x3`
3.  `(Date.now() % 0x3e8) / (0x4d2 - 0xea)` == `(Date.now() % 1000) / 1000`, do đó đoạn code này giá trị sẽ luôn từ 0 tới 1
4.  `i % 1` luôn bằng 0. 
5.  Trong javascript không có khai báo kiểu dữ liệu nên khi dùng phép toán `OR` sẽ bị ép kiểu thành `int` nên `((Date.now() % 0x3e8) / (0x4d2 - 0xea)) | i % 0x1` sẽ luôn bằng 0

Như vậy ta rút gọn hàm mã hóa như sau:
```javascript showLineNumbers
function encrypt(s) {
    let encrypted = []
    for (let i = 0; i < s.length; i++) {
        let x = (s[i].charCodeAt(0x0) + i * 0xf) % 0x80
        x += i > 0x0 ? encrypted[i - 1].charCodeAt(0) % 128 : 0xd
        x ^= 0x555
        x = ((x ^ ~0x0) >>> 0x0) & 0xff
        x = ~(x ^ (0x3)
        x = ((x >> 0x1f) + x) ^ (x >> 0x1f)
        encrypted.push(String.fromCharCode(x))
    }
    return encrypted.join("")
}
```

Vì hàm này sẽ mã hóa từng kí tự của một chuỗi và khi 1 kí tự mã hóa sẽ cộng với kí tự đứng trước vừa được mã hóa (nêú là kí tự đầu thì cộng với `0xd`) do đó ta có thể bruteforce từng kí tự. Bài này mình giải bằng python vì khi mình đọc file bằng javascript thì không ra đúng các kí tự trong file. Hàm mã hóa một kí tự bằng python:
```python showLineNumbers
def encrypt(c, prevc, i):
    x = (c + i * 0xf) % 0x80
    x += prevc % 128
    x ^= 0x555
    x = (x ^ ~0x0)  & 0xff
    x = ~(x ^ (0x3))
    x = ((x >> 0x1f) + x) ^ (x >> 0x1f)
    return x
``` 

Nếu kết quả trả về bằng với kí tự đã bị mã hóa ở vị trí đó trong **flag.txt** thì đó là kí tự ta cần tìm (để tránh trường hợp có nhiều kết quả mình sẽ chỉ mã hóa các kí tự trong `string.printable`). Code để lấy flag của mình:
```python showLineNumbers
import string


def encrypt(c, prevc, i):
    x = (c + i * 0xf) % 0x80
    x += prevc % 128
    x ^= 0x555
    x = (x ^ ~0x0)  & 0xff
    x = ~(x ^ (0x3))
    x = ((x >> 0x1f) + x) ^ (x >> 0x1f)
    return x

alpha = string.printable
buffer = open('flag.txt', 'r', encoding='utf8').read()
pt = ""
prev = 0xd
for i in range(len(buffer)):
    for c in alpha:
        tmp = encrypt(ord(c), prev, i)
        if tmp == ord(buffer[i]):
            pt += c
            break
    prev = ord(buffer[i])
    
print(pt)
```
File flag.txt:
> From: jared@business.biz <br/>
> To: dave@business.biz<br/>
> Subject: Fortune Telling Shenanigans<br/>
> Content-Type: text/html<br/>
> MIME-Version: 1.0<br/>
><br/>
> Hey Dave,<br/>
> I went to a fortune teller the other day and while she divined my future, she mentioned you, strangely enough.<br/>
> I don't know why you came up if it was *my%#fortune that was being read, but she said something about "your coworker Dave" and a "grave mistake," but I didn't read too much into it. She told me to send you this though:<br/>
>         sdctf{D0n't_b3_a_D4v3_ju5t_Use_AES_0r_S0me7h1ng}<br/>
> I'm not sure why she wanted you to know this gibberish. I can't seem to make heads or tails of it.<br/>
> Anyways are you coming to the company picnic this Saturday? I heard Carol from HR is bringing some of her world-famous<br/>
> deviled eggs.<br/>
> <br/>
> Best, <br/>
> Jared from Accounting <br/>
