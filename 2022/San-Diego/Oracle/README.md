# Oracle - Revenge 130 - 64 solves
![image](https://user-images.githubusercontent.com/92845822/167444726-c5552243-c81e-483d-89f6-7765edccf957.png)

Challenge này cung cấp 1 file bytecode. Dùng tool [jd-gui](https://github.com/java-decompiler/jd-gui) ta dễ dàng có được source code

```java
import java.io.Console;

public class Oracle {
  private static final int FLAG_LENGTH = 42;
  
  private static final byte[] CHECK = new byte[] { 
      48, 6, 122, -86, -73, -59, 78, 84, 105, -119, 
      -36, -118, 70, 17, 101, -85, 55, -38, -91, 32, 
      -18, -107, 53, 99, -74, 67, 89, 120, -41, 122, 
      -100, -70, 34, -111, 21, Byte.MIN_VALUE, 78, 27, 123, -103, 
      36, 87 };
  
  private static byte[] numbers;
  
  private static void firstPass() {
    for (byte b = 0; b < 42; b++)
      numbers[b] = (byte)(numbers[b] ^ 3 * b * b + 5 * b + 101 + b % 2); 
  }
  
  private static void secondPass() {
    byte[] arrayOfByte = new byte[42];
    for (byte b = 0; b < 42; b++)
      arrayOfByte[b] = (byte)(numbers[(b + 42 - 1) % 42] << 4 | (numbers[b] & 0xFF) >> 4); 
    numbers = arrayOfByte;
  }
  
  private static void thirdPass() {
    for (byte b = 0; b < 42; b++)
      numbers[b] = (byte)(numbers[b] + 7 * b * b + 31 * b + 127 + b % 2); 
  }
  
  private static void fail() {
    System.out.println("That's not the flag. Try again.");
    System.exit(1);
  }
  
  public static void main(String[] paramArrayOfString) {
    Console console = System.console();
    numbers = console.readLine("Enter flag: ", new Object[0]).getBytes();
    if (numbers.length != 42)
      fail(); 
    firstPass();
    secondPass();
    thirdPass();
    int i = 0;
    for (byte b = 0; b < 42; b++)
      i |= CHECK[b] ^ numbers[b]; 
    if (i != 0)
      fail(); 
    System.out.println("Good job. You found the flag!");
  }
}
```

Chương trình sẽ yêu cầu nhập vào 1 chuỗi string và sẽ bị mã hóa bằng 3 hàm `firstPass()`, `secondPass()`, `thirdPass()` rồi so sánh các giá trị đã mã hóa trước của flag trong mảng `CHECK`:

1. Hàm `firstpart` sẽ được XOR trước sau đó cộng giá trị lên rồi ép kiểu về
2. Hàm `secondPass()` sẽ dịch toàn bộ các bit sang phải 4 bit. Ví dụ: mảng byte có 3 phần tử `{123, -120, -50}` sẽ được biễu diễn như sau `{01111011, 10001000, 11001110}` (lưu ý là số âm sẽ biễu diễn dưới dạng bù 2), mảng sau khi chạy hàm: `{11100111, 10111000, 10001100}` 
3. Hàm `thirdPass()` cũng cộng giá trị lên rồi ép kiểu về

Code để lấy flag của mình:
```java
// import java.io.Console;
import java.util.Arrays;
public class RevOracle {

    private static final byte[] CHECK = new byte[] {
            48, 6, 122, -86, -73, -59, 78, 84, 105, -119,
            -36, -118, 70, 17, 101, -85, 55, -38, -91, 32,
            -18, -107, 53, 99, -74, 67, 89, 120, -41, 122,
            -100, -70, 34, -111, 21, Byte.MIN_VALUE, 78, 27, 123, -103,
            36, 87 };

    private static byte[] numbers;

    private static byte inv_firstPass(byte num, byte id) {
        byte tmp = (byte) (num ^ 3 * id * id + 5 * id + 101 + id % 2);
        return tmp;
    }
    
    private static void inv_secondPass() {
        int[] arrayOfByte = new int[42];
        for (byte b = 0; b < 42; b++) {
            arrayOfByte[b] = 0;
        }
        for (byte b = 41; b >= 0; b--) {
            arrayOfByte[b] |=  ((numbers[b] & 0xFF) << 4);
            arrayOfByte[(b + 42 - 1) % 42] |= ((numbers[b] & 0xFF) >> 4);
        }
        for (byte b = 0; b < 42; b++) {
            numbers[b] = (byte)arrayOfByte[b]; 
        }
    }

    private static void inv_thirdPass() {
        for (byte b = 0; b < 42; b++)
            numbers[b] = (byte) (CHECK[b] - 7 * b * b - 31 * b - 127 - b % 2);
    }
    public static void main(String[] paramArrayOfString) {
        numbers = new byte[42];
        byte[] flag = new byte[42];
        inv_thirdPass();
        System.out.println("number: " + Arrays.toString(numbers));
        inv_secondPass();
        System.out.println("number: " + Arrays.toString(numbers));
        boolean check = true;
        for (byte i = 0; i < 42; i++) {
            byte b = Byte.MIN_VALUE;
            for (;;) {
                byte tmp = inv_firstPass(b, i);
                if (tmp == numbers[i]) {
                    flag[i] = b;
                    check = true;
                    break;
                }
                if (b == Byte.MAX_VALUE)
                    break;
                b++;
            }
            if (!check) {
                System.out.println("Error");
                System.exit(1);
            }
            check = false;
        }
        System.out.println("number: " + Arrays.toString(flag));
        System.out.print("Flag: ");
        for (int i =0; i < 42; ++i)
            System.out.print((char)flag[i]);
    }
}
```
Hàm `firstPass()` mình dịch ngược lại có 1 số giá trị trả vể không phải chữ cái do đó tới đây mình sẽ bruteforce (hàm mã hóa từng kí tự nên ta cũng đơn giản brutefore từng kí tự)
> sdctf{u_f0und_th3_LANGu4ge_0f_th1s_0r4cl3}