# WannaGame ChampionShip CTF2022 - Crypto
## Complex Thing

Yêu cầu để tìm ra Flag đó chính là mọi người cần phải khôi phục được đa thức $f$ ban đầu với chỉ 1 nghiệm phức cho trước. Ý tưởng bài này là từ những ngày đầu mình nhập môn về lattice và ăn hành từ idol @maple3142 =)))

Có thể nói bài này là một trong những ứng dụng của thuật toán LLL ([wiki](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)) để tìm một phương trình mà có nghiệm là `r` cho trước nếu các điều kiện dưới đây thỏa

![](https://i.imgur.com/kazpdWQ.png)


Đầu tiên mọi người có thể thấy là mình dùng $1111$ bits để biểu diễn độ chính xác cho số chấm động, do đó khi scale về số nguyên sẽ rất lớn so với chỉ $128$ bits của các hệ số phương trình. Như vậy điều kiện đầu tiên đã thỏa còn với điều kiện thứ 2 thì vì đây là số chấm động nên sẽ không bằng 0 hoàn toàn nhưng sai số là đủ nhỏ để chấp nhận

```python!
bits = 1111
C = ComplexField(bits)
P = PolynomialRing(C, names='x')
(x,) = P.gens()
key = os.urandom(256)
coeff = [int.from_bytes(key[i:i+16], 'little') for i in range(0, len(key), 16)]
f = sum([a * x ** i for i, a in enumerate(coeff)])
r = random.choice(f.roots())[0]
```

Phương trình sẽ có dạng:

$$
a_0 + a_1r + \cdots + a_{14}r^{14} + a_{15}r^{15} \approx 0
$$

Với việc đây là nghiệm phức nên ta sẽ có 2 pt:

$$
a_0 + a_1r\_real + \cdots + a_{14}r\_real^{14} + a_{15}r\_real^{15} \approx 0 \\
a_1r\_imag + \cdots + a_{14}r\_imag^{14} + a_{15}r\_imag^{15} \approx 0 
$$

Mĩnh đã test và điều chỉnh các tham số để sai số khi scale về số nguyên ở khoàng $131$ bits kết hợp với việc các hệ số chỉ khoảng $128$ bit. Từ đây ta sẽ có một Lattice từ tổ hợp các vector sau trong không gian $\mathbf {Z}^{18}$:

$$
M = 
\left\{
\begin{bmatrix} 1 \\ 0 \\ 1 \\ \vdots \\ 0 \\ 0 \\ 0 \end{bmatrix},
\begin{bmatrix} r\_real \\ r\_imag \\ 0 \\ 1 \\ \vdots \\ 0 \\ 0 \end{bmatrix},
\begin{bmatrix} r\_real^2 \\ r\_imag^2 \\ 0 \\ 0 \\ 1 \\ \vdots \\ 0 \end{bmatrix}, 
\cdots, 
\begin{bmatrix} r\_real^{15} \\ r\_imag^{15} \\ 0 \\ 0 \\ 0 \\ \vdots \\ 1 \end{bmatrix}
\right\}
$$

Cơ sở toán học đằng sau thuật toán **LLL** thì rất nhiều, cái này thì mọi người tự tìm hiểu thôi. Còn ở đây chỉ cần biết là khi ta áp dụng thuật toán **LLL** sẽ cho ra kết quả là các tổ hợp tuyến tính của $M$ tức $a_i$'s sao cho:

$$
a_0
\begin{bmatrix} 1 \\ 0 \\ 1 \\ \vdots \\ 0 \\ 0 \\ 0 \end{bmatrix} +
a_1
\begin{bmatrix} r\_real \\ r\_imag \\ 0 \\ 1 \\ \vdots \\ 0 \\ 0 \end{bmatrix} +
\cdots +
a_{15}
\begin{bmatrix} r\_real^{15} \\ r\_imag^{15} \\ 0 \\ 0 \\ 0 \\ \vdots \\ 1 \end{bmatrix} = 
\begin{bmatrix} small\_error_1 \\ small\_error_2  \\ a_0 \\ a_1 \\ a_2 \\ \vdots \\ a_{15} \end{bmatrix}
$$

> The result vectors will need to be very small compared to the other vector in the equation

Code bằng sagemath:

```python!
real = [(r ** i)[0] for i in range(16)]
imag = [(r ** i)[1] for i in range(16)]
K = 2 ** (bits - 1)
M = matrix([
    [round(K * x) for x in real], # scale to ZZ
    [round(K * x) for x in imag]  # scale to ZZ
]).stack(matrix.identity(16))
M = M.T.LLL()[0].list()
print(M)
# [728997893725912360256392313432782126666, -714495899041231533525741364462759996543, -245290164185467455001056378471359788597, -267703462517877416315394176042215623236, -160692412082800135361084604738594833561, -220464095700527684208934466618859248904, -335272676007165940899861622211855555911, -243329974301837207240107683247354700773, -205272991369895188712869143138644144139, -304959696997955951280890150983342072439, -227250309429832708295110968244786942454, -294436422780995077669390758706474487289, -266199531520149242166891221654945499278, -325981186198153600017882593715584360248, -218613233424537448448294946971765311096, -91314567869344227150878293383433886572, -322890647764264578497394242926433450409, -130953951496112811727449899649153651360]
```

Khi đã đã có các hệ số thì mọi người chỉ cẩn tính `hash` và giải mã `AES` bình thường là có flag

```python!
key = []
for i in M[2:]:
    key.append(int(abs(i)).to_bytes(16, 'little'))
key = sha256(b''.join(key)).digest()
cipher = AES.new(key, AES.MODE_CBC, iv=enc[:16])
flag = unpad(cipher.decrypt(enc[16:]), 16)
print(flag.decode())
# W1{Lenstra_Lenstra_Lovasz_1s_y0ur_friend}
```

## Malicious Package

Bài này thì mình nghĩ là toán ít nhất trong cả mảng Cryptography nhưng có vẻ mọi người dễ bị lạc hướng.

Ban đầu mình chỉ cho 1 file `secure_installer.py` vì đơn giản là phần web không ảnh hưởng gì tới phần exploit cả vì dù sao vẫn là challenge crypto ngoài ra mình có xóa đi phần này
```python
def do_install(module_path: str):
    ''' 
    THIS FUNCTION WILL DO SOMETHING LIKE: python module_name/setup.py
    '''
    # STILL UNDER DEVELOPMENT
    pass
```
Code gốc:
```python!
def do_install(module_path: str):
    modules = glob.glob(module_path + "/**")
    modules.sort()
    for module in modules:
        if not os.path.isdir(module) or not os.path.exists(f'{module}/setup.py'):
            continue
        subprocess.run(
            ['python3', f'{module}/setup.py', 'install'],
            cwd=module_path,
            timeout=timeout,
            check=True
        )
```

Tuy nhiên mình cũng có để lại comment và code cũng thực thi tương tự những gì mình comment, chủ yếu là để tạo hoàn cảnh cho nó real real 1 xíu :smiling_face_with_smiling_eyes_and_hand_covering_mouth:.

Tóm lại là sau khi qua 7749 hàm thì cuối cùng server sẽ thực thi code có trong file `setup.py` (nếu có). Như vậy chỉ cần ta ghi đè code được vào file `setup.py` hoặc tạo 1 package mới luôn thì ta có thể khiến server chạy code của ta 1 cách thoải mái (Remote Code Excution)

Phân tích source code một chút, ta có thể thấy 2 hàm đáng chú ý sau:
```python!
def compute_hash_of_directory(directory: str) -> bytearray:
    """
    Compute a hash of all files contained in <directory>.
    """
    final_hash = bytearray(sha256().digest_size)
    files = glob.glob(directory + "/**", recursive=True)
    files.sort()
    files.remove(directory + '/')
    for path in files:
        rel_path = os.path.relpath(path, directory)
        h = sha256()
        print(rel_path)
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                h.update(rel_path.encode('utf-8'))
                h.update(b"\0")
                h.update(f.read())
        elif os.path.isdir(path):
            h.update((rel_path+'/').encode('utf-8') + b"\0")
        else:
            raise RuntimeError(
                "I don't know what you are doing but i don't like that!"
            )
        final_hash = xor(final_hash, h.digest())

    return final_hash


def verify_module_signature(
    path_to_module: str,
    signature_filename: str = "signature.bin"
) -> bool:
    path_to_verify = path_to_module + "/module"
    path_to_signature = path_to_module + "/" + signature_filename
    if not os.path.isdir(path_to_verify):
        return False
    if not os.path.isfile(path_to_signature):
        return False

    hash_value = compute_hash_of_directory(path_to_verify)
    with open(path_to_signature, "rb") as f:
        signature = f.read()
    print(signature)
    print(hash_value)
    vk = ecdsa.VerifyingKey.from_pem(
        public_key, hashfunc=sha256
    )
    return vk.verify_digest(signature, hash_value, allow_truncate=True)
```
Để ý ở hàm verify thì ta có thể thấy ở đây dùng thuật toán ecdsa để ký và xác thực chữ ký chứa xong file `signature.bin` bằng 1 public key cố định (có public)

Từ đây ta sẽ có 2 ý tưởng:

1. Từ file public key được cung cấp bằng 1 cách nào đó ta recover được private key và ký 1 package mới theo ý chúng ta
2. Tìm được hash collision với package ban đầu

Đối với cách 1 thì khi giải diễn ra mình thấy có 1 số bạn ngồi phân tích file public key của mình =))). Tuy nhiên khá là tiếc là mình dùng curve chuẩn của **NIST** tạo từ openssl nên có thể nói cách 1 là gần như không thể triển khai

Vậy còn cách thứ 2 thì sao? SHA256 được biết là không có 1 phương pháp cụ thể và công khai nào để tìm được collision tuy nhiên nếu mọi người để ý thì việc hash dữ liệu và xác thực của bài này không theo chuẩn thông thường.

Đầu tiên phải nói tới việc file zip khi gửi lên server phải có format sau:

```
package
¦   signature.bin
+---module
    ¦
    +---module1
    ¦    ¦   setup.py
    ¦    ¦   ...
    +---module2
    ¦    ¦   setup.py
    ¦    ¦   ...
    ¦   ...
```

Toàn bộ dữ liệu kể cả đường dẫn file nằm trong thư mục con`module` đều sẽ bị hash sau đó sẽ được xác thực với chữ ký trong `signature.bin`. Vấn đề ở chỗ thay vì gom dữ liệu lại và hash như bình thường thì chall này lại gom dữ liệu từng file và hash sau đó `xor` lại với nhau. Brokennnnn!

Lý do mình nói vậy đó là do tính chất của xor. Mọi người thường nghĩ nó là 1 toán tử bit bình thường tuy nhiên nếu các bạn có kiến thức về trường hữu hạn sẽ biết là xor 2 bit với nhau thực chất là phép toán $+$ trên $\mathbb{F}_{2}$. 
$$
0 + 0 = 0 \pmod{2} \\
0 + 1 = 1 \pmod{2} \\
1 + 0 = 1 \pmod{2} \\
1 + 1 = 0 \pmod{2} \\
$$

`sha256` sẽ cho ta 256 bit tức tức là hash của 1 data bất kì sẽ là 1 vector trong không gian $\mathbb{F}_{2}^{256}$. Việc tìm đụng độ của hàm hash này là rất khó nên ta sẽ xem đó là 1 hàm random. Lúc này bài toàn sẽ được quy về 1 hướng khác đó chính là tìm 1 tổ hợp tuyến tính từ 1 tập hữu hạn vector do ta tạo ra sao cho kết quả là 1 vector ta mong muốn.

$$
x_1
\begin{bmatrix} a_{1.1} \\ a_{1.2} \\ a_{1.3} \\ \vdots \\ a_{1.254} \\ a_{1.255} \\ a_{1.256}  \end{bmatrix} +
x_2
\begin{bmatrix} a_{2.1} \\ a_{2.2} \\ a_{2.3} \\ \vdots \\ a_{2.254} \\ a_{2.255} \\ a_{2.256}  \end{bmatrix} +
\cdots +
x_{256}
\begin{bmatrix} a_{256.1} \\ a_{256.2} \\ a_{256.3} \\ \vdots \\ a_{256.254} \\ a_{256.255} \\ a_{256.256}  \end{bmatrix} = 
\begin{bmatrix} b_{1} \\ b_{2}  \\ b_{3}  \\ \vdots \\ b_{254}  \\ b_{255}  \\ b_{256}  \end{bmatrix}
$$

Hay tóm gọn lại: 
$$
\begin{align}
X*A &= B \\ 
\Leftrightarrow A^{\top}*X &= B \\
\end{align}
$$

+ $A$ là ma trận được tạo từ từ 1 tập vector ta random ra
+ $A^{\top}$ là ma trận chuyển vị của $A$
+ $B$ là vector ta mong muốn
+ $X$ sẽ là vector ta cần tìm

Đến đây lại quay về đại số tuyến tính =))) và ta sẽ cần giải 1 hệ phương trình tuyến tính trên $\mathbb{F}_{2}$ với A là ma trận hệ số. Điều kiện để hệ nghiệm đó là ma trận mở rộng $\overline{A}$ phải có cùng bậc với $A^{\top}$

$$
\overline{A} = 
\begin{pmatrix}
a_{1.1} & a_{2.1} & \cdots &a_{255.1} & a_{256.1} &\big| & b_{1}\\
a_{1.2} & a_{2.2} & \cdots &a_{255.2} & a_{256.2} &\big| & b_{2}\\
\vdots & \vdots & \ddots & \vdots & \vdots &\big| & \vdots\\
a_{1.255} & a_{2.255} & \cdots &a_{255.255} & a_{256.255} &\big| & b_{255}\\
a_{1.256} & a_{2.256} & \cdots &a_{255.256} & a_{256.256} &\big| & b_{256}\\
\end{pmatrix}
$$

Để đơn giản thì bạn cứ tạo ma trận $A$ sao cho có bậc bằng với số chiều trong không gian là được. Lúc này bạn có thể ép ra được bất kì vector nào mong muốn. Việc còn lại là 1 chút kĩ năng về coding và reverse shell là mọi người có thể lấy được flag.

Script của mình: [link](https://github.com/m1dm4n/CTF-WriteUp/tree/main/MyChallenge/Wannagame2022/malicious_update/sol)

+ Note 1: code lần này mình có update so với hôm mới thi xong chủ yếu là để nhìn nó gọn hơn thôi :v
+ Note 2: hàm `rmtree` khá nguy hiểu nên mọi người cẩn thận kiểm tra đường dẫn trước khi sử dụng

## Weirdaaaaeeees

Bằng 1 thế lực thần bí nào đó thì mình đã quyết định làm 1 file binary =)))

Thật ra thì lý do mình làm vậy chủ yếu để kiểm tra độ nhận diện thuật toán thôi. Hai thuật toán mã hóa mà mình cho đó chính là từ DES và AES, mình cũng copy code của 2 thằng trên từ github thôi nên cũng có thể nói là khá gọn và mình cũng không strip file binary (làm vậy thì thành RE mất :v).

Source:
+ DES: https://github.com/dhuertas/DES/blob/master/des.c
+ AES: https://github.com/arusson/dfa-aes/blob/main/src/aes.c

Sơ lược vê bài này thì hàm mã hóa sẽ nhìn như sau:
```c
__int64 __fastcall encrypt(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  encencenc(a1, a4, a2);
  encencenc(a1 + 8, a4 + 8, a2);
  return enc2(a1, a4, a3);
}
```
+ `encencenc` là hàm về DES
+ `enc2` là hàm về AES

Có thể thấy là phần DES đã bị vô hiệu hoàn toàn vì mình set nhầm a2 thành a1 ở hàm `enc2`, thêm vào đó đáng lẽ sẽ là `encenc` tức 2 lần mã hóa và mọi người sẽ áp dụng việc semi-weak key của AES tại đây :crying_cat_face:. 

Nhưng có vẻ sai sót này của mình đã khiến bài dễ hơn rất nhiều (tức là các bạn có thể skip phần DES). Đó cũng là lý do mình quyết định nếu ai hỏi về phần này thì mình cũng sẽ nói thẳng luôn nhưng có vẻ hơi ế nên mình quyết định để nó thành **intend** luôn

Như vậy ta sẽ chỉ lo phần AES. Chính xác thì sẽ là AES 4 round => **Exploitable**

### AES 4 round
Nói về cryptanalyst với AES 4 round thì mình nghĩ đây là nguồn hay nhất mọi người có thể tham khảo (https://www.davidwong.fr/blockbreakers/square_2_attack4rounds.html). Theo cách hiểu của mình việc dùng 4 round aes thì khi bạn thay đổi 1 bit bất kì thì việc khuếch tán sẽ không đủ mạnh và dày 

![](https://i.imgur.com/chbbt4O.png)

Do đó nếu bạn đoán 1 byte key con bất kì tại round cuối sẽ có nhiều cơ sở để xác định tính chuẩn xác của nó hơn và **Square Attack** đã chứng mình là ta chỉ cần tối đa 256 ciphertext là đủ (các plaintext của nó chỉ được phép có sự khác biệt ở 1 byte). Khi ta đoán 1 byte của `round_key` tại round đó sẽ có 1 xác suất nhất định xảy ra nhiều trường hợp và việc có thông tin của plaintext có thể giúp chúng ta thu hẹp lại số lượng `key`

Trong challenge của mình thì không cho mọi người chọn plaintext tuy nhiên mỗi round game đều có đủ 256 ciphertext và thỏa mản điều kiện để sử dụng Square Attack.

```python!
# Copy directly from https://github.com/p4-team/ctf/tree/master/2016-03-12-0ctf/peoples_square
def round2master(rk):
    Nr = 4
    Nk = 4
    Nb = 4
    w = []
    for i in range(Nb*(Nr+1)):
        w.append([0, 0, 0, 0])
    i = 0
    while i < Nk:
        w[i] = [rk[4*i], rk[4*i+1], rk[4*i+2], rk[4*i+3]]
        i = i+1
    j = Nk
    while j < Nb*(Nr+1):
        if (j % Nk) == 0:
            w[j][0] = w[j-Nk][0] ^ sbox[w[j-1][1] ^ w[j-2][1]] ^ Rcon[Nr - j//Nk][0]
            for i in range(1, 4):
                w[j][i] = w[j-Nk][i] ^ sbox[w[j-1][(i+1) % 4] ^ w[j-2][(i+1) % 4]]
        else:
            w[j] = XorWords(w[j-Nk], w[j-Nk-1])
        j = j+1
    m = []
    for i in range(16, 20):
        for j in range(4):
            m.append(w[i][j])
    return m

def backup(ct, byteGuess, byteIndex):
    t = ct[byteIndex] ^ byteGuess
    return invsbox[t]


def integrate(index):
    potential = []
    for candidateByte in range(256):
        sum = 0
        for ciph in ciphertexts:
            oneRoundDecr = backup(ciph, candidateByte, index)
            sum ^= oneRoundDecr
        # print(sum)
        if sum == 0:
            potential.append(candidateByte)
    # exit(1)
    return potential


def integral():
    candidates = []
    for i in range(16):
        candidates.append(integrate(i))
    print('candidates', candidates)
    for roundKey in product(*candidates):
        masterKey = round2master(roundKey)
        plain1 = bytes(decrypt4rounds(ciphertexts[0], masterKey))
        plain2 = bytes(decrypt4rounds(ciphertexts[1], masterKey))

        if plain2[:4] in plain1[:4]:
            print('solved:', masterKey)
            return masterKey
key = integral()
# Example output since key is randomized
# candidates [[41, 113], [14], [85, 120], [138], [154], [231], [61, 215], [33], [141, 231], [174], [31], [124], [174], [10, 69, 219], [36, 163, 213], [22, 145, 152]]
# solved: [69, 95, 60, 0, 14, 224, 50, 55, 56, 65, 173, 95, 79, 49, 128, 170]
```

Bắt đầu quá trình giải mã và lấy flag thôi:
```python!
for i in range(256):
    io.recvuntil(b':\n')
    ct = list(bytes.fromhex(io.recvline().strip().decode()))
    pt = decrypt4rounds(ct, key)
    io.sendlineafter(b':\n', f"{pt[-1]:02x}".encode())

io.recvuntil(b'SECRET:\n')
line = io.recvline().decode().strip()
print(line)
flag = list(bytes.fromhex(line))
print(bytes(decrypt4rounds(flag[:16], key)).decode(), end='')
print(bytes(decrypt4rounds(flag[16:32], key)).decode(), end='')
print(bytes(decrypt4rounds(flag[32:48], key)).decode(), end='')
print(bytes(decrypt4rounds(flag[48:], key)).decode())

# io.interactive()
io.close()
# W1{M4ster_0f_EEE_DES_w34k_key_4nd_SQUARE_4tack_FOR_4_ROUND_AES!}
```

Mình không nghĩ mình lại ẩu vậy :crying_cat_face:. Bad author!!!

Dù sao thì hy vọng mọi người thích mấy **Challenge** của mình. Năm sau nếu còn được ra đề cho WannaGame thì mình sẽ cố gắng và nắn nót hơn để cải thiện chất lượng cho các **Challenge**
