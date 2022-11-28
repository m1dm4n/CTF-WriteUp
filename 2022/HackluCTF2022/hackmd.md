# Hack.<span>lu CTF 2022</span>

## Crypto - Linear Starter - 166 solves
~~Bạn mình solve lúc mình đang ngủ rồi =)))~~

## Crypto - Deltawings Delivery Time - 33 solves
> At Deltawings we like do deploy our own crypto and we like fast delivery times. We have this new blazingly fast hmac scheme and thought of a brilliant idea: Let our customers test the implementation to win a free food coupon. Of course we've limited the amount of traffic that can be send to our server - we don't want it burning as our chicken wings are already spicy enough!

[Attachments](https://github.com/m1dm4n/HackluCTF2022/tree/main/deltawings_delivery_time/public)

Sau khi test trên server 1 chút và đọc source thì mình thấy server sẽ cho ta 2 lựa chọn là:
1. Tính hmac của đoạn text chúng ta nhập vào và debug cho xem chúng ta thời gian hoàn thành của mỗi block và mỗi vị trí. Chỉ cho phép 1 session tính `hmac` của tối đa 250 bytes
2. Kiểm tra nếu text chúng ta nhập vào trùng với `key` hiện tại của server thì trả về `FLAG`

Phân tích kĩ hàm `hmac` thì mình thấy đây là các bước để tính ra kết quả:
1. Nếu độ dài văn bản không chia hết cho 16 thì sẽ chạy hàm `pad` để lấp đủ độ dài thỏa mãn yêu cầu
2. Tạo giá trị khởi đầu `state = 0000000000000000ffffffffffffffff`
3. Chia văn bản thành các block 16 bytes
4. Với mỗi block sẽ chạy 16 rounds tương đương với mỗi bytes trong block
5. Nếu byte tại vị trí đó `xor` với byte tại cùng vị trí trong `key` ra 1 byte mà có số lượng bit 1 lớn hơn 3 thì sẽ sự dụng hàm `hash1` để hash hàm hiện tại ngược lại sẽ sử dụng hàm hash2
6. Quay lại bước 4 với block tiếp theo. Nếu không còn sẽ kết thúc và in ra kết quả cuối cùng

Ngoài ra sau khi thực hiện xong bước 5 chương trình sẽ cho chúng ta biết thời gian hiện tại. Tới đây thì mình thấy có mùi **side channel attack**.

Và khi đọc hàm `hash1` và `hash2` thì nó đúng là vậy thật :smiley:

`hash1`:
```cpp=
void hash1(struct Bytearray *input){
    SHA256_CTX ctx;
    byte outbuf[32];

    sha256_init(&ctx);
    sha256_update(&ctx,input->data,input->sz);
    sha256_final(&ctx,outbuf);
    memcpy(input->data,outbuf,16);
}
```
`hash2`:
```cpp=
void hash2(struct Bytearray *input){
    for (int i=0;i<50;i++){
        blake2b(input->data,16,input->data,input->sz,0,0);
    }
}
```
Hàm `hash2` thực hiện lâu hơn hàm `hash1` rất nhiều lần, do đó ta dựa vào thời gian ta có thể xác định được hàm nào đã được thực thi. Từ đó ta có thể biết $x$ ($x=block_i\oplus key_i$) có số lượng bit $1$ lớn hơn $3$ hay không

Vậy làm sao để tìm được key? 

Lấy vị dụ $block_1$ là $5$ và chương trình cho ta biết tại vị trí đó chạy hàm `hash1` thì có tới $163$ số mà `xor` với $5$ có số lượng bit $1$ lớn hơn $3$. Tuy nhiên nếu chúng ta chạy với $1$ mẫu khác có $block_1$ là $199$ và chương trình chạy hàm `hash2` thì lúc này từ $163$ số đó ta chỉ còn $55$ số thỏa cả 2 yêu cầu. Như vậy càng nhiều điều kiện thì số lượng đáp án sẽ càng giảm

Nếu để ý thì `input` chúng ta nhập và lúc nào cũng được `pad` nên ta có thể lợi dụng điểm này để debug được tối đa 250 đoạn `text`.

Sau khi có đủ số lượng mẫu thì ta sẽ xem ở vị trí thứ $i$ của `key`, từ 0 tới 255 có số nào thỏa được nhiều điều kiện nhất thì đó có thể là byte tại vị trí $i$ của `key` (Vì mình sẽ chọn 1 mức thời gian cố định để xác định liệu đó là `hash1` hay `hash2` do đó không phải lúc nào cũng chính xác nên có thể bị nhiễu)

Mình thấy sử dụng khoảng 100 mẫu thử là đủ và mốc thời gian để phân biệt là $100000$nanosecond. [Script solve.py](https://github.com/m1dm4n/HackluCTF2022/blob/main/deltawings_delivery_time/solve.py)

Output:
```
[+] Opening connection to ddt.flu.xxx on port 10201: Done
[+] Trying byte:
    Got enough 100 payloads.
[*] Good byte for index 0: 247 (95.0%)
[*] Good byte for index 1: 119 (98.0%)
[*] Good byte for index 2: 182 (95.0%)
[*] Good byte for index 3: 133 (96.0%)
[*] Good byte for index 4: 67 (96.0%)
[*] Good byte for index 5: 45 (95.0%)
[*] Good byte for index 6: 235 (96.0%)
[*] Good byte for index 7: 139 (96.0%)
[*] Good byte for index 8: 186 (96.0%)
[*] Good byte for index 9: 38 (95.0%)
[*] Good byte for index 10: 122 (98.0%)
[*] Good byte for index 11: 74 (94.0%)
[*] Good byte for index 12: 54 (98.0%)
[*] Good byte for index 13: 4 (96.0%)
[*] Good byte for index 14: 7 (96.0%)
[*] Good byte for index 15: 154 (95.0%)
[+] Found session Key: f777b685432deb8bba267a4a3604079a
[+] FLAG: Correct! Enjoy your coupon :) flag{now_its_time_to_grab_your_free_food!_?v=8Dax_Ex5Rt0}
[*] Closed connection to ddt.flu.xxx port 10201
```

## Crypto - Recipe Vault - 17 solves
> We have an extra secure encryption system for our recipes.<br>It uses organic, locally sourced crypto from the 90s!
Sadly, there is no decryption routine, and we stored the key on a machine to which we forgot the password. BUT: We have the source code and you can connect to the encryption routine via TCP. Could you please decrypt this for us:<br>
184aed743987e240d2715d41fa0d450aa3ac24aecce9dbc5e86d5f69aa1677d2

[Attachments](https://github.com/m1dm4n/HackluCTF2022/tree/main/Recipe_Vault)

Câu này thì mình cũng không biết phân tích sao =))

Mình gửi lên sever `plaintext` và server sẽ trả về `ciphertext` thôi. Còn đoạn hex trong mô tả là `FLAG` đã bị mã hóa 

Sau khi osint 1 hồi thì mình biết nó là mã hóa **MAGENTA**. Osint thêm xíu thì mình tìm được tài liệu về [Cryptanalysis of Magenta](https://www.schneier.com/wp-content/uploads/2016/02/paper-magenta.pdf). Và có 1 đoạn mình thấy hứng thú
> We would also wish to note that due to the symmetry of the key scheduling, encryption and decryption are identical except for the order of the two halves of the plaintexts and ciphertexts. Therefore, given a ciphertext, one can decrypt it by swapping its two halves, reencrypting the result, and swapping again. Note that this attack uses an adaptive access to an encryption device and cannot be used to recover the key

Check lại hàm mã hóa:
```python=
def encrypt(blk, something_key):
    blk = np.copy(blk)
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[0:2])
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[2:4])

    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[4:6])
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[6:8])

    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[8:10])
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[10:12])

    return blk
```

Tóm là là ta không cần **cryptanalysis** để khôi phục key mà chỉ cần lấy cái ciphertest đã bị mã hóa, và gửi lên sever để mã hóa lần nữa nhưng lúc này ta hoán nửa đầu và cuối của `ciphertext` và bùm.... Giải mã thành công =))))))

Thật ra thì lý do tại sao lại giải mã đơn giản như trên mà không cần `key` thì các bạn có thể để ý hàm `combination_magic` có tính chất đối xứng (tức là cùng 1 `key` thì mã hóa bằng hàm này và giải mã cũng bằng hàm này luôn). Hàm giải mã sẽ trông như sau:
```python=
def decrypt(blk, something_key):
    blk = np.copy(blk)
    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[2:4])
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[0:2])

    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[6:8])
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[4:6])

    blk[2:4] = combination_magic(blk[2:4], blk[0:2], something_key[10:12])
    blk[0:2] = combination_magic(blk[0:2], blk[2:4], something_key[8:10])

    return blk
```

Mỗi block là 16 bytes và `FLAG` gồm 2 block do đó ta chỉ cần gửi cho server payload như sau (`FLAG` đang ở dạng hex): 
```python
flag = flag[16:32] + flag[:16] + flag[48:] + flag[32:48] 
```
Swap lại như ban đầu và `unhex` là ra flag:
```
d2715d41fa0d450a184aed743987e240e86d5f69aa1677d2a3ac24aecce9dbc5
[x] Opening connection to flu.xxx on port 12001
[x] Opening connection to flu.xxx on port 12001: Trying 31.22.123.45
[+] Opening connection to flu.xxx on port 12001: Done
[*] Closed connection to flu.xxx port 12001
666c61677b786372697370796770756361626c65776974686761726c6963787d
flag{xcrispygpucablewithgarlicx}
```

## Crypto - Faulty Ingredient - 25 solves
> My boss said, that we should better encrypt the secret ingredient of our delicious sauce. But when I used my own AES, I noticed that sometimes, I got totally wrong values. Since I had a great crypto class at my evening school, I managed to nail the error down to the input of the Mix Columns in Round 9. I can't say how, but when the error occurs, exactly one random byte in every column of the state changes. I ran some tests, solely for myself, but my dumb intern posted them on Fluxstagram when making one of his stupid selfies. Well anyway, I hope nobody can use this to recover the main key and decrypt our secret ingredient!

[Attachments](https://github.com/m1dm4n/HackluCTF2022/tree/main/Faulty_Ingredient/public)


Theo mình thấy thì đây là câu hay nhất và mình học được nhiều nhất. Tuy nhiên để phân tích toàn bộ câu này một cách chi tiết nhất thì mất rất nhiều thời gian :crying_cat_face: nên mình sẽ nói một cách khái quát nhất vậy. Còn bạn nào muốn tìm hiểu sâu hơn thì có thể tham khảo blog này: [Differential Fault Analysis on White-box AES Implementations](https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html) 

Trong source code người ta cho mình thì cũng chỉ có 1 file AES tự code của tác giả y chang AES gốc tuy nhiên có thêm 1 hàm mã hóa và ở round thứ 9 thì cứ 1 byte bất kì mỗi 4 bytes sẽ bị lỗi (xor với 1 số random)

Vậy thì tại sao điều này lại làm 1 hệ mã hóa đạt chuẩn của **NIST** về mọi mặt lại gãy ?

Đầu tiên mọi người cần hiểu AES hoặc động trên một trường hữu hạn đặc biệt GF($2^8$). Nên phép xor được hiểu là phép cộng trên trường này

Bây giờ mình sẽ biểu diễn block AES trước khi trải qua `mixcolumn` ở round thứ 9 của cả `ciphertext` gốc $C_i$ và cái bị lỗi $F_i$ như sau:

\begin{equation*}
\begin{pmatrix}
A & E & I & M \\
B & F & J & N \\
C & G & K & O \\
D & H & L & P
\end{pmatrix}
\text{and}
\begin{pmatrix}
A+X & E & I & M \\
B & F & J & N \\
C & G & K & O \\
D & H & L & P
\end{pmatrix}
\end{equation*}

Lưu ý là mình sẽ chỉ biểu diễn duy nhất 1 việc bị lỗi trên 1 cột để dễ hình dung (Đề bài bị lỗi trên cả 4 cột và cứ 4 bytes của 1 block là 1 cột).

Sau khi `mixcolumn` ở round 9:
\begin{equation*}
\begin{pmatrix}
2A+3B+C+D & \cdots & \cdots & \cdots \\
A+2B+3C+D & \cdots & \cdots & \cdots \\
A+B+2C+3D & \cdots & \cdots & \cdots \\
3A+B+C+2D & \cdots & \cdots & \cdots
\end{pmatrix}
\text{and}
\begin{pmatrix}
2A+2X+3B+C+D & \cdots & \cdots & \cdots \\
A+X+2B+3C+D & \cdots & \cdots & \cdots \\
A+X+B+2C+3D & \cdots & \cdots & \cdots \\
3A+3X+B+C+2D & \cdots & \cdots & \cdots
\end{pmatrix}
\end{equation*}

Sau khi `add_roundkey` $K_9$ ở round 9 và kết thúc round:
\begin{equation*}
\begin{pmatrix}
2A+3B+C+D+K_{9,0} & \cdots & \cdots & \cdots \\
A+2B+3C+D+K_{9,1} & \cdots & \cdots & \cdots \\
A+B+2C+3D+K_{9,2} & \cdots & \cdots & \cdots \\
3A+B+C+2D+K_{9,3} & \cdots & \cdots & \cdots
\end{pmatrix}
\text{and}
\begin{pmatrix}
2A+2X+3B+C+D+K_{9,0} & \cdots & \cdots & \cdots \\
A+X+2B+3C+D+K_{9,1} & \cdots & \cdots & \cdots \\
A+X+B+2C+3D+K_{9,2} & \cdots & \cdots & \cdots \\
3A+3X+B+C+2D+K_{9,3} & \cdots & \cdots & \cdots
\end{pmatrix}
\end{equation*}

Sau khi trải qua `SubBytes`(viết tắt là `S`), `ShiftRows` và `AddRoundKey` $K_{10}$:

\begin{equation*}
\begin{pmatrix}
S(2A+3B+C+D+K_{9,0})+K_{10,0} \qquad \cdots \qquad \cdots \qquad \cdots \\
\cdots \qquad \cdots \qquad \cdots \qquad S(A+2B+3C+D+K_{9,1})+K_{10,13}\\
\cdots \qquad \cdots \qquad S(A+B+2C+3D+K_{9,2})+K_{10,10} \qquad \cdots \\
\cdots \qquad S(3A+B+C+2D+K_{9,3})+K_{10,7} \qquad \cdots \qquad \cdots
\end{pmatrix}
\text{and}
\begin{pmatrix}
S(2A+2X+3B+C+D+K_{9,0})+K_{10,0} \qquad \cdots \qquad \cdots \qquad \cdots \\
\cdots \qquad \cdots \qquad \cdots \qquad S(A+X+2B+3C+D+K_{9,1})+K_{10,13}\\
\cdots \qquad \cdots \qquad S(A+X+B+2C+3D+K_{9,2})+K_{10,10} \qquad \cdots \\
\cdots \qquad S(3A+3X+B+C+2D+K_{9,3})+K_{10,7} \qquad \cdots \qquad \cdots
\end{pmatrix}
\end{equation*}

Ta có:
\begin{equation*}
O_0 = S(2A+3B+C+D+K_{9,0})+K_{10,0} \\
O_7 = S(A+2B+3C+D+K_{9,1})+K_{10,7} \\
O_{10} = S(A+B+2C+3D+K_{9,2})+K_{10,10} \\
O_{13} = S(3A+B+C+2D+K_{9,3})+K_{10,13} \\
\end{equation*}

\begin{equation*}
O'_0 = S(2A+3B+C+D+K_{9,0})+K_{10,0} \\
O'_7 = S(A+2B+3C+D+K_{9,1})+K_{10,7} \\
O'_{10} = S(A+B+2C+3D+K_{9,2})+K_{10,10} \\
O'_{13} = S(3A+B+C+2D+K_{9,3})+K_{10,13} \\
\end{equation*}

\begin{align}
=>O_0 + O'_0 &= S(2A+3B+C+D+K_{9,0}) +K_{10,0} + S(2A+2X+3B+C+D+K_{9,0}) +K_{10,0} \\
&= S(2A+3B+C+D+K_{9,0}) + S(2A+2X+3B+C+D+K_{9,0})
\end{align}

Tương tự:
\begin{align}
O_7 + O'_7 &= S(A+2B+3C+D+K_{9,1}) + S(A+X+2B+3C+D+K_{9,1}) \\
O_{10} + O'_{10} &= S(A+B+2C+3D+K_{9,2}) + S(A+X+B+2C+3D+K_{9,2}) \\
O_{13} + O'_{13} &= S(3A+B+C+2D+K_{9,3}) + S(3A+3X+B+C+2D+K_{9,3}) \\
\end{align}

Nếu ta đặt $Y_i$ là giá trị thứ i của cột đầu tiên của `block` sau khi kết thúc round 9 (trong hàm mã hóa bình thường) thì ta có 4 phương trình sau:

\begin{align}
O_0 + O'_0 &= S(Y_0) + S(Y_0+2X) \\
O_7 + O'_7 &= S(Y_1) + S(Y_1+X)  \\
O_{10} + O'_{10} &= S(Y_2) + S(Y_2+X)  \\
O_{13} + O'_{13} &= S(Y_3) + S(Y_3+3X)  \\
\end{align}

$O_i$ và $O'_i$ đều là các giá trị ta đã biết và với mỗi thằng `X` từ trong 256 giá trị của GF($2^8$) và 4 vị trị bất kì trên cột
```python=
for fault_ind in range(4):
    for j in range(256):
        e = [0]*fault_ind + [j] + [0]*(3 - fault_ind)
        state_e = [0, 0, 0, 0]
        state_e[0] = gf_mul123(e[0], 2) ^ gf_mul123(e[1], 3) ^ gf_mul123(e[2], 1) ^ gf_mul123(e[3], 1)
        state_e[1] = gf_mul123(e[0], 1) ^ gf_mul123(e[1], 2) ^ gf_mul123(e[2], 3) ^ gf_mul123(e[3], 1)
        state_e[2] = gf_mul123(e[0], 1) ^ gf_mul123(e[1], 1) ^ gf_mul123(e[2], 2) ^ gf_mul123(e[3], 3)
        state_e[3] = gf_mul123(e[0], 3) ^ gf_mul123(e[1], 1) ^ gf_mul123(e[2], 1) ^ gf_mul123(e[3], 2)
        # print(state_e)
        Xs.add(tuple(state_e))
```
Ta sẽ tìm giá trị $Y_0$ tương ứng thỏa phương trình thứ nhất, từ những thẳng thỏa trước đó ta sẽ tìm tiếp những giá trị $Y_1$ thỏa tiếp phương trình thứ 2... Cứ như vậy ta sẽ tìm được các tập 4 giá trị $Y_i$ thỏa đc 4 phương trình trên với thằng $X$ tương ứng (vì $X$ là random nên ta sẽ lấy toàn bộ nghiệm).
```python=
idxs = [0, 13, 10, 7] # inverse shift rows for col 1
Ys = set()
needs = [ft[ind] ^ ct[ind] for ind in idxs]
def dfs(X, cur, l):
    if l == 4:
        Ys.add(tuple(cur))
        return
    for y in range(256):
        if sbox[y] ^ sbox[y ^ X[l]] == needs[l]:
            cur.append(y)
            dfs(X, cur, l+1)
            cur.pop(-1)
for X in Xs:
    dfs(X, [], 0)
print(len(Ys))
```
Output:
```
976
```
Chạy rất nhanh dù nghe thì có vẻ là vét cạn tìm tất cả 5 bytes thỏa mãn chưa kể ta còn không biết vị trí chính xác của bytes bị lỗi trong 4 bytes trên cột đó. Tuy nhiên thưucj nghiệm đã chứng minh với mỗi thẳng $X$ tương ứng chỉ có số lượng rất nhỏ các giá trị $Y_i$ trong miền $[0,255]$ có thể thỏa mãn được phương trình $i$ tương ứng thôi.

Ngoài ra việc chúng ta có nhiều hơn 1 cặp `ciphertext` và `faulttext` sẽ giúp chúng ta giao các đáp án lại với nhau giúp giảm 2 tập nghiệm lại với nhau giúp giảm bớt trường hợp.

Sau khi có được các thằng $Y_i$ thì nhớ lại 4 phương trình ta có ở trước đó:
\begin{align}
O_0 &= S(2A+3B+C+D+K_{9,0})+K_{10,0}  = S(Y_0) + K_{10,0}\\
O_7 &= S(2A+3B+C+D+K_{9,1})+K_{10,7}  = S(Y_7) + K_{10,7}\\
O_{10} &= S(2A+3B+C+D+K_{9,2})+K_{10,10} = S(Y_{10}) + K_{10,10}\\
O_{13} &= S(2A+3B+C+D+K_{9,3})+K_{10,13} = S(Y_{13}) + K_{10,13}\\
\end{align}

Như vậy là chúng ta sẽ kiếm được những thằng có thể là $K_{10,0}, K_{10,7}, K_{10,10}, K_{10,13}$ và 1 trong các thằng đó sẽ là đáp án đúng. Đề bài cũng cho chúng ta bị lỗi ở cả 4 cột do đó ta có thể hoàn toàn khôi phục hoàn toàn $K_{10}$ dùng ở `add_roundkey` thứ 10. Vì hàm để mở rộng `key` (hay `key_schedule_128`) là hàm 2 chiều nên ta có thể khôi phục lại `key` bí mật ban đầu 1 cách dễ dàng
```python=
def reverse_key_schedule(round_key: bytes, aes_round: int):
    assert len(round_key) * 8 == 128

    def xor_bytes(aa, bb) -> bytes:
        return bytes(a ^ b for a, b in zip(aa, bb))
    for i in range(aes_round - 1, -1, -1):
        a2 = round_key[0:4]
        b2 = round_key[4:8]
        c2 = round_key[8:12]
        d2 = round_key[12:16]

        d1 = xor_bytes(d2, c2)
        c1 = xor_bytes(c2, b2)
        b1 = xor_bytes(b2, a2)
        a1 = xor_bytes(a2, g(d1, i))

        round_key = a1 + b1 + c1 + d1

    return round_key
```

Script hoàn chỉnh: [Link](https://github.com/m1dm4n/HackluCTF2022/blob/main/Faulty_Ingredient/dfa.py)

Mình thậm chí chỉ cẩn 2 cặp `ciphertext` và `faultext` là đủ để tìm được 1 đáp án duy nhất. Output:
```
976
992
1232
1024
1328
1008
1008
976
key at round 10: [178, 54, 86, 62, 78, 61, 224, 159, 86, 231, 247, 114, 96, 170, 82, 188]
key: 25acfc955fa52864657da3c67384eef8
flag{Th3_s3cr3t_inGreDient_is_oni0n_powd3r_h3h3}
```

Write up của giải này chỉ có vậy thôi. Dù được đánh giá là giải top nhưng mình thấy có vẻ nhìn chung Crypto không ác như những giải top mình chơi trước đó :crying_cat_face:. Tóm lại thì mình ấn tượng nhất vẫn là câu **Faulty Ingredient** thôi vì mình khá non trong cryptanalyst. Hy vọng là mình cũng truyền được xíu kiến thức của bản thân. Bye!
