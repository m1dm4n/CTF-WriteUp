import java.io.Console;

public class Oracle {

    private static final byte[] CHECK = new byte[] {
            48, 6, 122, -86, -73, -59, 78, 84, 105, -119,
            -36, -118, 70, 17, 101, -85, 55, -38, -91, 32,
            -18, -107, 53, 99, -74, 67, 89, 120, -41, 122,
            -100, -70, 34, -111, 21, Byte.MIN_VALUE, 78, 27, 123, -103,
            36, 87 };

    private static byte[] numbers;

    private static void firstPass() {
        for (byte b = 0; b < 42; b++)
            numbers[b] = (byte) (numbers[b] ^ 3 * b * b + 5 * b + 101 + b % 2);
    }

    private static void secondPass() {
        byte[] arrayOfByte = new byte[42];
        for (byte b = 0; b < 42; b++)
            arrayOfByte[b] = (byte) (numbers[(b + 42 - 1) % 42] << 4 | (numbers[b] & 0xFF) >> 4);
        numbers = arrayOfByte;
    }

    private static void thirdPass() {
        for (byte b = 0; b < 42; b++)
            numbers[b] = (byte) (numbers[b] + 7 * b * b + 31 * b + 127 + b % 2);
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
