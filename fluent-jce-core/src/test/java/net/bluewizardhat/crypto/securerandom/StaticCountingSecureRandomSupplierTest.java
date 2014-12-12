package net.bluewizardhat.crypto.securerandom;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class StaticCountingSecureRandomSupplierTest {
	private static final int RESEED_MAX_BYTES = 512;
	private static final int RESEED_MAX_SECONDS = 1;

	private static StaticCountingSecureRandomSupplier secureRandomSupplier = StaticCountingSecureRandomSupplier.getInstance();

	@Before
	public void setup() {
		secureRandomSupplier.setReseedMaxBytes(RESEED_MAX_BYTES);
	}

	@After
	public void reset() {
		secureRandomSupplier.setDefaultReseedSettings();
	}

	/**
	 * Test we get the same supplier if we do not request any random data.
	 */
	@Test
	public void testSameSupplier() {
		SecureRandom random1 = secureRandomSupplier.currentSecureRandom();
		SecureRandom random2 = secureRandomSupplier.currentSecureRandom();
		assertNotNull(random1);
		assertTrue(random1 == random2);
	}

	/**
	 * Tests the SecureRandom is re-seeded after generating enough data
	 */
	@Test
	public void testSimpleReseed() {
		SecureRandom random1 = secureRandomSupplier.currentSecureRandom();
		random1.nextBytes(new byte[RESEED_MAX_BYTES]);
		SecureRandom random2 = secureRandomSupplier.currentSecureRandom();
		assertFalse(random1 == random2);
	}

	/**
	 * Tests the SecureRandom is re-seeded after generating enough keys
	 */
	@Test
	public void testReseedWithKeys() throws Exception {
		// Setup
		SecureRandom random1 = secureRandomSupplier.currentSecureRandom();
		int keyLenght = Math.min(Cipher.getMaxAllowedKeyLength("AES"), 256);

		// Exercise
		int rounds = RESEED_MAX_BYTES * 8 / keyLenght;
		for (int i = 0; i < rounds; i++) {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(keyLenght, secureRandomSupplier.currentSecureRandom());
			keyGenerator.generateKey();
		}

		// Verify
		SecureRandom random2 = secureRandomSupplier.currentSecureRandom();
		assertFalse(random1 == random2);
	}

	@Test
	public void testReseedAfterTime() throws Exception {
		secureRandomSupplier.setReseedMaxSeconds(RESEED_MAX_SECONDS);
		SecureRandom random1 = secureRandomSupplier.currentSecureRandom();
		Thread.sleep((RESEED_MAX_SECONDS + 1) * 1000);
		SecureRandom random2 = secureRandomSupplier.currentSecureRandom();
		assertFalse(random1 == random2);
	}
}
