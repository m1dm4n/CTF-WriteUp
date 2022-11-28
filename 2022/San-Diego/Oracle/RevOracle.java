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
