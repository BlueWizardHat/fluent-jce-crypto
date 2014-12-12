package net.bluewizardhat.crypto.factory;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.security.Key;
import java.util.Arrays;
import java.util.Random;

import net.bluewizardhat.crypto.BaseFluentEncryptionEngine;
import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;

import org.junit.Before;
import org.junit.Test;

public class TripleDesFactoryTest {
	private SymmetricEncryptionEngine[] engines = {
			TripleDesFactory.usingTripleDesCtr(),
			TripleDesFactory.usingTripleDesCbc(),
			TripleDesFactory.usingTripleDesCfb(),
			TripleDesFactory.usingTripleDesEcb(),
		};

	private Random random = new Random();

	private byte[] randomBytes;

	// This is the size to ask for when you want a 192 bit long key
	private int askForKeySize = 168;

	// This is an actual key size that 3DES supports
	private int actualKeySize = 192;

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
			Key key = TripleDesFactory.generateKey(askForKeySize);
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
			KeyedFluentEncryptionEngine keyedengine = engine.withPassword("bullimong", actualKeySize);

			// Setup
			byte[] expectedResult = randomBytes;

			// Exercise
			byte[] encrypted = keyedengine.encryptData(expectedResult);
			byte[] actualResult = keyedengine.decryptData(encrypted);

			// Verify
			assertFalse(Arrays.equals(expectedResult, encrypted));
			assertArrayEquals(expectedResult, actualResult);
		}
	}
}
