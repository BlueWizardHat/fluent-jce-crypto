package net.bluewizardhat.crypto.factory;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.security.Key;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;

import net.bluewizardhat.crypto.BaseFluentEncryptionEngine;
import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class AesFactoryTest {
	private SymmetricEncryptionEngine[] engines = {
			AesFactory.usingAesCtr(),
			AesFactory.usingAesCfb(),
			AesFactory.usingAesCbc(),
			AesFactory.usingAesEcb()
		};

	private static int testKeySize;

	private Random random = new Random();

	private byte[] randomBytes;

	@BeforeClass
	public static void classSetup() throws Exception {
		// Figure out which key size to use depending on system configuration
		testKeySize = Math.min(256, Cipher.getMaxAllowedKeyLength("AES"));
		System.out.println("Running AesFactory tests with keysize " + testKeySize);
	}

	@Before
	public void setup() throws Exception {
		// Generate some random data to test with
		randomBytes = new byte[2000 + random.nextInt(2000)];
		random.nextBytes(randomBytes);
	}

	/**
	 * Simple test to ensure that all engines provided by this factory actually work
	 */
	@Test
	public void testKeyBasedEncryption() {
		for (BaseFluentEncryptionEngine engine : engines) {
			// Setup
			Key key = AesFactory.generateKey(testKeySize);
			KeyedFluentEncryptionEngine keyedEngine = engine.withKey(key);

			// Setup
			byte[] expectedResult = randomBytes;

			// Exercise
			byte[] encrypted = keyedEngine.encryptData(expectedResult);
			byte[] actualResult = keyedEngine.decryptData(encrypted);

			// Verify
			assertFalse(Arrays.equals(expectedResult, encrypted));
			assertArrayEquals(expectedResult, actualResult);
		}
	}

	/**
	 * Simple test to ensure that all engines provided by this factory actually work
	 */
	@Test
	public void testPasswordBasedEncryption() {
		for (SymmetricEncryptionEngine engine : engines) {
			// Setup
			KeyedFluentEncryptionEngine keyedEngine = engine.withPassword("bullimong", testKeySize);

			// Setup
			byte[] expectedResult = randomBytes;

			// Exercise
			byte[] encrypted = keyedEngine.encryptData(expectedResult);
			byte[] actualResult = keyedEngine.decryptData(encrypted);

			// Verify
			assertFalse(Arrays.equals(expectedResult, encrypted));
			assertArrayEquals(expectedResult, actualResult);
		}
	}
}
