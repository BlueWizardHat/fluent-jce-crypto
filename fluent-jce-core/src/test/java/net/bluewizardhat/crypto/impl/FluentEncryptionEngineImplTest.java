package net.bluewizardhat.crypto.impl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;

import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;
import net.bluewizardhat.crypto.exception.BadHmacException;
import net.bluewizardhat.crypto.exception.CryptoException;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class FluentEncryptionEngineImplTest {

	/**
	 * Any algorithm that uses an initialization vector will do
	 */
	private SymmetricEncryptionEngine encryptionEngine =
		FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CBC/PKCS5Padding", 16);

	/**
	 * Any algorithm that does not use an initialization vector will do,
	 * AES in ECB mode does not use an iv.
	 */
	private SymmetricEncryptionEngine ivLessEncryptionEngine =
		FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/ECB/PKCS5Padding", 0);

	private static int testKeySize;

	private Random random = new Random();

	private byte[] randomBytes;
	private Key key;

	@Rule
	public ExpectedException expectedException = ExpectedException.none();

	@BeforeClass
	public static void classSetup() throws Exception {
		// Figure out which key size to use depending on system configuration
		testKeySize = Math.min(256, Cipher.getMaxAllowedKeyLength("AES"));
		System.out.println("Running FluentEncryptionEngineImpl tests with keysize " + testKeySize);
	}

	@Before
	public void setup() throws Exception {
		// Generate a random key
		key = KeyGenerator.generateKey("AES", testKeySize);

		// Generate some random data to test with
		randomBytes = new byte[2000 + random.nextInt(2000)];
		random.nextBytes(randomBytes);
	}

	@Test
	public void testPasswordBasedEncryption() {
		// Setup
		String password = "asdfgh";
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = encryptionEngine.withPassword(password, testKeySize).encryptData(expectedResult).getResult();
		byte[] actualResult = encryptionEngine.withPassword(password, testKeySize).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testPasswordBasedEncryptionBadPassword() {
		// Setup
		String password = "asdfgh";
		String badPassword = "asdfgg";
		expectedException.expect(CryptoException.class); // May not happen with all encryption engines, but will with this one
		expectedException.expectMessage("not properly padded");

		// Exercise
		byte[] encrypted = encryptionEngine.withPassword(password, testKeySize).encryptData(randomBytes).getResult();
		encryptionEngine.withPassword(badPassword, testKeySize).decryptData(encrypted);
	}

	@Test
	public void testPasswordBasedEncryptionBadPasswordWithHac() {
		// Setup
		String password = "asdfgh";
		String badPassword = "asdfgg";
		expectedException.expect(BadHmacException.class);
		expectedException.expectMessage("HMAC does not match");

		// Exercise
		byte[] encrypted = encryptionEngine.withHmac().withPassword(password, testKeySize).encryptData(randomBytes).getResult();
		encryptionEngine.withHmac().withPassword(badPassword, testKeySize).decryptData(encrypted);
	}

	@Test
	public void testEncryptionWithBytes() {
		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = encryptionEngine.withKey(key).encryptData(expectedResult).getResult();
		byte[] actualResult = encryptionEngine.withKey(key).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testEncryptionWithBytesBadKey() {
		// Setup
		Key badKey = KeyGenerator.generateKey("AES", testKeySize);
		expectedException.expect(CryptoException.class); // May not happen with all encryption engines, but will with this one
		expectedException.expectMessage("not properly padded");

		// Exercise
		byte[] encrypted = encryptionEngine.withKey(key).encryptData(randomBytes).getResult();
		encryptionEngine.withKey(badKey).decryptData(encrypted);
	}

	@Test
	public void testEncryptionWithBytesBadKeyWithHmac() {
		// Setup
		Key badKey = KeyGenerator.generateKey("AES", testKeySize);
		expectedException.expect(BadHmacException.class);
		expectedException.expectMessage("HMAC does not match");

		// Exercise
		byte[] encrypted = encryptionEngine.withHmac().withKey(key).encryptData(randomBytes).getResult();
		encryptionEngine.withHmac().withKey(badKey).decryptData(encrypted);
	}

	@Test
	public void testEncryptionWithCipherStreams() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;
		ByteArrayOutputStream encryptStream = new ByteArrayOutputStream();

		// Exercise
		try (OutputStream out = encryptionEngine.withKey(key).createEncryptingOutputStream(encryptStream).getResult()) {
			out.write(expectedResult);
			out.flush();
		}
		byte[] encrypted = encryptStream.toByteArray();

		ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encrypted);
		byte[] actualResult;
		try (InputStream in = encryptionEngine.withKey(key).createDecryptingInputStream(encryptedStream)) {
			actualResult = readInputStreamFully(in);
		}

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testEncryptWithStreamDecryptWithBytes() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;
		ByteArrayOutputStream encryptStream = new ByteArrayOutputStream();

		// Exercise
		try (OutputStream out = encryptionEngine.withKey(key).createEncryptingOutputStream(encryptStream).getResult()) {
			out.write(expectedResult);
			out.flush();
		}
		byte[] encrypted = encryptStream.toByteArray();

		byte[] actualResult = encryptionEngine.withKey(key).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testEncryptWithBytesDecryptWithStream() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = encryptionEngine.withKey(key).encryptData(expectedResult).getResult();

		ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encrypted);
		byte[] actualResult;
		try (InputStream in = encryptionEngine.withKey(key).createDecryptingInputStream(encryptedStream)) {
			actualResult = readInputStreamFully(in);
		}

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testIvLessEncryptionWithBytes() {
		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = ivLessEncryptionEngine.withKey(key).encryptData(expectedResult).getResult();
		byte[] actualResult = ivLessEncryptionEngine.withKey(key).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testIvLessPasswordBasedEncryption() {
		// Setup
		String password = "asdfgh";
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = ivLessEncryptionEngine.withPassword(password, testKeySize).encryptData(expectedResult).getResult();
		byte[] actualResult = ivLessEncryptionEngine.withPassword(password, testKeySize).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testIvLessEncryptionWithCipherStreams() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;
		ByteArrayOutputStream encryptStream = new ByteArrayOutputStream();

		// Exercise
		try (OutputStream out = ivLessEncryptionEngine.withKey(key).createEncryptingOutputStream(encryptStream).getResult()) {
			out.write(expectedResult);
			out.flush();
		}
		byte[] encrypted = encryptStream.toByteArray();

		ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encrypted);
		byte[] actualResult;
		try (InputStream in = ivLessEncryptionEngine.withKey(key).createDecryptingInputStream(encryptedStream)) {
			actualResult = readInputStreamFully(in);
		}

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testIvLessEncryptWithStreamDecryptWithBytes() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;
		ByteArrayOutputStream encryptStream = new ByteArrayOutputStream();

		// Exercise
		try (OutputStream out = ivLessEncryptionEngine.withKey(key).createEncryptingOutputStream(encryptStream).getResult()) {
			out.write(expectedResult);
			out.flush();
		}
		byte[] encrypted = encryptStream.toByteArray();

		byte[] actualResult = ivLessEncryptionEngine.withKey(key).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testIvLessEncryptWithBytesDecryptWithStream() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = ivLessEncryptionEngine.withKey(key).encryptData(expectedResult).getResult();

		ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encrypted);
		byte[] actualResult;
		try (InputStream in = ivLessEncryptionEngine.withKey(key).createDecryptingInputStream(encryptedStream)) {
			actualResult = readInputStreamFully(in);
		}

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	private byte[] readInputStreamFully(InputStream source) throws IOException {
		ByteArrayOutputStream target = new ByteArrayOutputStream();
		byte[] buffer = new byte[4096];
		int read;
		while (true) {
			read = source.read(buffer);
			if (read == -1) {
				break;
			}
			target.write(buffer, 0, read);
		}
		return target.toByteArray();
	}
}
