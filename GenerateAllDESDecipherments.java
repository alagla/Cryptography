import java.util.*;
import java.text.*;

/*
 * This program prints all plaintexts from a known ciphertext by iterating
 * over all possible keys.  For this version of DES, a key is 9 bits so there
 * are 512 possible ciphertexts for a particular plaintext.
 *
 * The code was written by John Rogers on February 9th, 2017.
 *
 */

public class GenerateAllDESDecipherments {

	static final int NumberOfRounds = 4;

	// This method returns a string containing ones and zeroes
	// representing the binary value of the integer n.
	public static String formatBinary(int n, int bitCount) {
		Stack<Integer> bits = new Stack<Integer>();
		for (int i = 0; i < bitCount; i++) {
			int bit = n & 0b1;
			bits.push(bit);
			n = n >> 1;
		}
		StringBuilder s = new StringBuilder();
		while (!bits.empty()) {
			int bit = bits.pop();
			s.append(bit);
		}
		return s.toString();
	}

	// This method generates an array of sub-keys from the key.
	// NB: This only generates four sub-keys.  A better version
	// would use the constant NumberOfRounds to generate the list.
	public static int[] generateKeySchedule(int key) {
		int key1 = (key & 0b111111110) >> 1;
		int key2 = ((key & 0b011111111) << 0) + ((key & 0b000000000) >> 9);
		int key3 = ((key & 0b001111111) << 1) + ((key & 0b100000000) >> 8);
		int key4 = ((key & 0b000111111) << 2) + ((key & 0b110000000) >> 7);
		int[] keySchedule = {0, key1, key2, key3, key4};
		return keySchedule;
	}

	// This method implements the expansion performed on the plaintext
	// bits coming in to the f-box.
	public static int expand(int r) {
		int bit1 = (r & 0b100000) >> 5;
		int bit2 = (r & 0b010000) >> 4;
		int bit3 = (r & 0b001000) >> 3;
		int bit4 = (r & 0b000100) >> 2;
		int bit5 = (r & 0b000010) >> 1;
		int bit6 = (r & 0b000001) >> 0;
		int expandedR = (bit1 << 7) + (bit2 << 6) + (bit4 << 5) + (bit3 << 4) +
		                (bit4 << 3) + (bit3 << 2) + (bit5 << 1) + (bit6 << 0);
		return expandedR;
	}

	// This implements S-box 1.  Each S-box takes as input a 4-bit integer for which
	// The leftmost bit is used as a row index and the three rightmost bits are used
	// as a column index.
	public static int s1box(int n) {
		int[][] s1values = {{0b101, 0b010, 0b001, 0b110, 0b011, 0b100, 0b111, 0b000},
						    {0b001, 0b100, 0b110, 0b010, 0b000, 0b111, 0b101, 0b011}};
		int fourBitValue = n & 0b1111;
		int rowIndex = fourBitValue >> 3;
		int columnIndex = fourBitValue & 0b111;
		return s1values[rowIndex][columnIndex];
	}

	// This implements S-box 2.  Each S-box takes as input a 4-bit integer for which
	// The leftmost bit is used as a row index and the three rightmost bits are used
	// as a column index.
	public static int s2box(int n) {
		int[][] s2values = {{0b100, 0b000, 0b110, 0b101, 0b111, 0b001, 0b011, 0b010},
						  {0b101, 0b011, 0b000, 0b111, 0b110, 0b010, 0b001, 0b100}};
		int fourBitValue = n & 0b1111;
		int rowIndex = fourBitValue >> 3;
		int columnIndex = fourBitValue & 0b111;
		return s2values[rowIndex][columnIndex];
	}

	// This implements the f-box.  See the diagram in figure 4.1 on p. 115
	// of the textbook for details.
	public static int f(int r, int key) {
		r = expand(r);
		r = r ^ key;
		int rLeft4bits = (r & 0b11110000) >> 4;
		int rRight4bits = (r & 0b1111) >> 0;
		int s1 = s1box(rLeft4bits);
		int s2 = s2box(rRight4bits);
		return (s1 << 3) + s2;
	}

	// This method takes a string of zeroes and ones and
	// computes and returns the integer value represented
	// by those bit values.
	public static int parseBinary(String s) {
		int n = 0;
		for (int i = 0; i < s.length(); i++) {
			n *= 2;
			if (s.charAt(i) == '1') n += 1;
		}
		return n;
	}

	public static int encrypt(int plaintext, int key) {
		int[] keySchedule = generateKeySchedule(key);

		int left =  (plaintext & 0b111111000000) >> 6;
		int right = (plaintext & 0b000000111111);

		// Encryption
		for (int i = 1; i <= NumberOfRounds; i++) {
			// Each iteration of this loop represents one round of encryption.
			int nextLeft = right;
			int nextRight = f(right, keySchedule[i]) ^ left;
			left = nextLeft;
			right = nextRight;
		}
		return left*64+right;
	}

	public static int decrypt(int ciphertext, int key) {
		int[] keySchedule = generateKeySchedule(key);

		int left =  (ciphertext & 0b111111000000) >> 6;
		int right = (ciphertext & 0b000000111111);

		// Decryption
		for (int i = NumberOfRounds; i >= 1; i--) {
			// Each iteration of this loop represents one round of decryption.
			// Note that decryption is simply the reverse of encryption.
			int previousRight = left;
			int previousLeft = f(left, keySchedule[i]) ^ right;
			left = previousLeft;
			right = previousRight;
		}
		return left*64+right;
	}

	public static void main(String... args) {
		if (args.length != 1) {
			System.err.println("Usage: java GenerateAllDESDecipherments <ciphertext string>");
			System.exit(1);
		}

		String ciphertextString = args[0];

		if (ciphertextString.length() != 12) {
			System.err.println("The ciphertext must contains 12 ones and zeroes.");
			System.exit(1);
		}
		for (Byte c: ciphertextString.getBytes()) {
			if (c != '0' && c != '1') {
				System.err.println("The ciphertext must contains 12 ones and zeroes.");
				System.exit(1);
			}
		}

		int ciphertext = parseBinary(ciphertextString);

		System.out.printf("Ciphertext: %12s (%4d)\n", ciphertextString, ciphertext);
		System.out.printf("%-15s\t%-15s\n", "Key", "Plaintext");
		for (int key = 0; key < 512; key++) {
			int plaintext = decrypt(ciphertext, key);
			System.out.printf("%9s (%3d)\t", formatBinary(key, 9), key);
			System.out.printf("%12s (%4d)\n", formatBinary(plaintext, 12), plaintext);
		}
	}
}
