package net.bluewizardhat.crypto.factory;

import java.security.KeyPair;

import net.bluewizardhat.crypto.AsymmetricEncryptionEngine;
import net.bluewizardhat.crypto.CombinedEncryptionEngine;
import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.impl.CombinedEncryptionEngineImpl;
import net.bluewizardhat.crypto.impl.FluentEncryptionEngineImpl;

/**
 * Example of a factory for encryption with RSA.
 */
public class RsaFactory {
	/**
	 * Returns an {@link AsymmetricEncryptionEngine} that implements RSA
	 *
	 * Be aware when using RSA that the cipher cannot encrypt data larger then the key, for example
	 * with a 2048 bit key you can maximum encrypt 245 bytes. To encrypt more than 245 bytes you
	 * should use generate a random symmetric key then encrypt the symmetric key with RSA but encrypt
	 * the actual data with the symmetric cipher. See {@linkplain #usingRsaAndAesCfb()}
	 *
	 * The {@link AsymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static AsymmetricEncryptionEngine usingRsa() {
		return FluentEncryptionEngineImpl.getAsymmetricEncryptionEngine("RSA", "RSA/ECB/PKCS1Padding");
	}

	/**
	 * Returns an {@link CombinedEncryptionEngine} that implements RSA + AES in CFB mode. This
	 * combined encryption can be used to encrypt or decrypt larger amounts of data than the
	 * engine returned by {@linkplain #usingRsa()}
	 *
	 * The {@link CombinedEncryptionEngine} returned by this method is thread-safe.
	 */
	public static CombinedEncryptionEngine usingRsaAndAesCfb() {
		return new CombinedEncryptionEngineImpl(usingRsa(), AesFactory.usingAesCfb());
	}

	/**
	 * Generate a random {@link KeyPair} that can be used with the algorithm implemented by this factory.
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static KeyPair generateKeyPair(int keyLength) {
		return KeyGenerator.generateKeyPair("RSA", keyLength);
	}

}
