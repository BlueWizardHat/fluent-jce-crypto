package net.bluewizardhat.crypto;

import java.security.Key;

/**
 * Base interface for a encryption engine with a fluent API.
 *
 * An encryption engine with a fluent API. An example of usage could be something like:
 * <code><pre>
 * byte[] encryptedData = AesFactory.usingAesCbc().withKey(key).encryptData(rawData);
 * </pre></code>
 */
public interface BaseFluentEncryptionEngine {
	/**
	 * Returns a {@link KeyedFluentEncryptionEngine} that can encrypt and decrypt using the given {@link Key}.
	 *
	 * <p>Note this method does not validate that the key is valid for the implemented algorithm, thus encryption and decryption
	 * may fail even though {@link #withKey} is successful.
	 */
	public KeyedFluentEncryptionEngine withKey(Key key);

	/**
	 * Returns the algorithm implemented by this {@link BaseFluentEncryptionEngine}.
	 */
	public String getAlgorithm();

	/**
	 * Returns the transformation implemented by this {@link BaseFluentEncryptionEngine}.
	 */
	public String getTransformation();
}
