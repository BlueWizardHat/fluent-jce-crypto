package net.bluewizardhat.crypto.impl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Random;

import net.bluewizardhat.crypto.CombinedEncryptionEngine;
import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.factory.AesFactory;
import net.bluewizardhat.crypto.factory.RsaFactory;

import org.junit.Before;
import org.junit.Test;

public class CombinedEncryptionEngineImplTest {
	
	private CombinedEncryptionEngine encryptionEngine = new CombinedEncryptionEngineImpl(RsaFactory.usingRsa(), AesFactory.usingAesCfb());

	private Random random = new Random();

	private byte[] randomBytes;
	private KeyPair keyPair;

	@Before
	public void setup() throws Exception {
		// Generate random keys
		keyPair = KeyGenerator.generateKeyPair("RSA", 2048);

		// Generate some random data to test with
		randomBytes = new byte[2000 + random.nextInt(2000)];
		random.nextBytes(randomBytes);
	}

	@Test
	public void testEncryptionWithBytes() {
		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = encryptionEngine.withKey(keyPair.getPublic(), 128).encryptData(expectedResult);
		byte[] actualResult = encryptionEngine.withKey(keyPair.getPrivate(), 128).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testEncryptionWithCipherStreams() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;
		ByteArrayOutputStream encryptStream = new ByteArrayOutputStream();

		// Exercise
		try (OutputStream out = encryptionEngine.withKey(keyPair.getPublic(), 128).createEncryptingOutputStream(encryptStream)) {
			out.write(expectedResult);
			out.flush();
		}
		byte[] encrypted = encryptStream.toByteArray();

		ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encrypted);
		byte[] actualResult;
		try (InputStream in = encryptionEngine.withKey(keyPair.getPrivate(), 128).createDecryptingInputStream(encryptedStream)) {
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
		try (OutputStream out = encryptionEngine.withKey(keyPair.getPublic(), 128).createEncryptingOutputStream(encryptStream)) {
			out.write(expectedResult);
			out.flush();
		}
		byte[] encrypted = encryptStream.toByteArray();

		byte[] actualResult = encryptionEngine.withKey(keyPair.getPrivate(), 128).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}

	@Test
	public void testEncryptWithBytesDecryptWithStream() throws Exception {
		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = encryptionEngine.withKey(keyPair.getPublic(), 128).encryptData(expectedResult);

		ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encrypted);
		byte[] actualResult;
		try (InputStream in = encryptionEngine.withKey(keyPair.getPrivate(), 128).createDecryptingInputStream(encryptedStream)) {
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
