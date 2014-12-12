package net.bluewizardhat.crypto.factory.bouncy;

import java.security.Security;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;
import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.impl.FluentEncryptionEngineImpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Example of a factory utilizing the Bounce Castle providers for encryption with Camellia.
 * See also <a href="http://www.bouncycastle.org/">The Legion of the Bouncy Castle</a> website.
 */
public class CamelliaFactory {

	/**
	 * Camellia is not part of standard Java, so we make sure to initialize the provider from bouncy castle.
	 */
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Camellia in CTR mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingCamelliaCtr() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Camellia", "Camellia/CTR/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Camellia in CFB mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingCamelliaCfb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Camellia", "Camellia/CFB/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Camellia in CBC mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingCamelliaCbc() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Camellia", "Camellia/CBC/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Camellia in ECB mode with PKCS5 padding.
	 * ECB is the least safe mode for Camellia.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingCamelliaEcb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Camellia", "Camellia/ECB/PKCS5Padding", 0);
	}

	/**
	 * Generate a random {@link SecretKey} that can be used with the algorithm implemented by this factory.
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(int keyLength) {
		return KeyGenerator.generateKey("Camellia", keyLength);
	}
}
