package net.bluewizardhat.crypto.impl;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;

import org.junit.Test;

/**
 * Tests for ensuring that the encrypted format does not change.
 */
public class FluentEncryptionEngineImplFormatStabilityTest {

	private String password = "V3ry53cr37Pa55w0rd";
	private String unencryptedFile = "src/test/resources/lorem-ipsum.png";
	private String encryptedFile = "src/test/resources/lorem-ipsum.enc";
	private String encryptedHmacFile = "src/test/resources/lorem-ipsum-hmac.enc";
	private String encryptedIvLessFile = "src/test/resources/lorem-ipsum-noiv.enc";
	private String encryptedIvLessHmacFile = "src/test/resources/lorem-ipsum-noiv-hmac.enc";

	private SymmetricEncryptionEngine encryptionEngine = FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CBC/PKCS5Padding", 16);
	private SymmetricEncryptionEngine ivLessEncryptionEngine = FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/ECB/PKCS5Padding", 0);

	@Test
	public void decrypt() throws IOException {
		// Setup
		FileInputStream in = new FileInputStream(encryptedFile);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		byte[] expectedResult = loadUnencryptedFile();

		// Exercise
		decryptStream(encryptionEngine.withPassword(password, 128), in, bOut);
		byte[] actualResult = bOut.toByteArray();

		// Verify
		assertTrue(Arrays.equals(actualResult, expectedResult));
	}

	@Test
	public void decryptWithHmac() throws IOException {
		// Setup
		FileInputStream in = new FileInputStream(encryptedHmacFile);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		byte[] expectedResult = loadUnencryptedFile();

		// Exercise
		decryptStream(encryptionEngine.withHmac().withPassword(password, 128), in, bOut);
		byte[] actualResult = bOut.toByteArray();

		// Verify
		assertTrue(Arrays.equals(actualResult, expectedResult));
	}

	@Test
	public void decryptIvLess() throws IOException {
		// Setup
		FileInputStream in = new FileInputStream(encryptedIvLessFile);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		byte[] expectedResult = loadUnencryptedFile();

		// Exercise
		decryptStream(ivLessEncryptionEngine.withPassword(password, 128), in, bOut);
		byte[] actualResult = bOut.toByteArray();

		// Verify
		assertTrue(Arrays.equals(actualResult, expectedResult));
	}

	@Test
	public void decryptIvLessWithHmac() throws IOException {
		// Setup
		FileInputStream in = new FileInputStream(encryptedIvLessHmacFile);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		byte[] expectedResult = loadUnencryptedFile();

		// Exercise
		decryptStream(ivLessEncryptionEngine.withHmac().withPassword(password, 128), in, bOut);
		byte[] actualResult = bOut.toByteArray();

		// Verify
		assertTrue(Arrays.equals(actualResult, expectedResult));
	}

	private byte[] loadUnencryptedFile() throws IOException {
		File inFile = new File(unencryptedFile);
		byte[] buffer = new byte[(int) inFile.length()];
		try (FileInputStream source = new FileInputStream(unencryptedFile)) {
			int total = source.read(buffer);
			if (total < buffer.length) {
				fail("Could not read file");
			}
		}

		return buffer;
	}

	private long decryptStream(KeyedFluentEncryptionEngine engine, InputStream source, OutputStream target) throws IOException {
		try (InputStream in = engine.createDecryptingInputStream(source)) {
			return streamCopy(in, target);
		}
	}

	private long streamCopy(InputStream source, OutputStream target) throws IOException {
		byte[] buffer = new byte[17 * 1024];
		long total = 0;
		int read;
		while (true) {
			read = source.read(buffer);
			if (read == -1) {
				break;
			}
			target.write(buffer, 0, read);
			total += read;
		}
		target.flush();
		return total;
	}
}
