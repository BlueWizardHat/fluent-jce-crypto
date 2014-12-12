package net.bluewizardhat.crypto.factory;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;
import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.impl.FluentEncryptionEngineImpl;

/**
 * Example of a factory for encryption with AES (Advanced Encryption Standard).
 */
public class AesFactory {

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in CTR mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesCtr() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CTR/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in CFB mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesCfb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CFB/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in CBC mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesCbc() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CBC/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in ECB mode with PKCS5 padding.
	 * ECB is the least safe mode for AES.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesEcb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/ECB/PKCS5Padding", 0);
	}

	/**
	 * Generate a random {@link SecretKey} that can be used with the algorithm implemented by this factory.
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(int keyLength) {
		return KeyGenerator.generateKey("AES", keyLength);
	}
}
