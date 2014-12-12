package net.bluewizardhat.crypto.factory;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Random;

import net.bluewizardhat.crypto.AsymmetricEncryptionEngine;
import net.bluewizardhat.crypto.CombinedEncryptionEngine;

import org.junit.Test;

public class RsaFactoryTest {
	private Random random = new Random();

	private byte[] randomBytes;

	@Test
	public void testEncryption() {
		// Generate some random data to test with
		randomBytes = new byte[245];
		random.nextBytes(randomBytes);

		// Setup
		KeyPair keyPair = RsaFactory.generateKeyPair(2048);
		AsymmetricEncryptionEngine engine = RsaFactory.usingRsa();

		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = engine.withKey(keyPair.getPublic()).encryptData(expectedResult);
		byte[] actualResult = engine.withKey(keyPair.getPrivate()).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}


	@Test
	public void testCombinedEncryption() {
		// Generate some random data to test with
		randomBytes = new byte[2000 + random.nextInt(2000)];
		random.nextBytes(randomBytes);

		// Setup
		KeyPair keyPair = RsaFactory.generateKeyPair(2048);
		CombinedEncryptionEngine engine = RsaFactory.usingRsaAndAesCfb();

		// Setup
		byte[] expectedResult = randomBytes;

		// Exercise
		byte[] encrypted = engine.withKey(keyPair.getPublic(), 128).encryptData(expectedResult);
		byte[] actualResult = engine.withKey(keyPair.getPrivate(), 128).decryptData(encrypted);

		// Verify
		assertFalse(Arrays.equals(expectedResult, encrypted));
		assertArrayEquals(expectedResult, actualResult);
	}
}
