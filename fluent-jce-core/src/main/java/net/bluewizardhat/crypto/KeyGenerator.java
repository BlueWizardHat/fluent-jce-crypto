package net.bluewizardhat.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.securerandom.SecureRandomSupplier;
import net.bluewizardhat.crypto.securerandom.StaticCountingSecureRandomSupplier;

/**
 * Helper class to generate encryption keys.
 */
public class KeyGenerator {
	private static SecureRandomSupplier secureRandomSupplier = StaticCountingSecureRandomSupplier.getInstance();

	/**
	 * Generate a random {@link SecretKey} that can be used with the given algorithm for use with symmetric ciphers such as AES, Blowfish, etc..
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(String algorithm, int keyLength) {
		if (algorithm == null) {
			throw new IllegalArgumentException("algorithm may not be null");
		}
		try {
			javax.crypto.KeyGenerator keyGenerator = javax.crypto.KeyGenerator.getInstance(algorithm);
			keyGenerator.init(keyLength, secureRandomSupplier.currentSecureRandom());
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(algorithm, e);
		}
	}

	/**
	 * Generate a random {@link KeyPair} that can be used with the given algorithm for use with asymmetric ciphers such as RSA, etc..
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static KeyPair generateKeyPair(String algorithm, int keyLength) {
		if (algorithm == null) {
			throw new IllegalArgumentException("algorithm may not be null");
		}
		try {
			java.security.KeyPairGenerator keyGenerator = java.security.KeyPairGenerator.getInstance(algorithm);
			keyGenerator.initialize(keyLength, secureRandomSupplier.currentSecureRandom());
			return keyGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(algorithm, e);
		}
	}
}
