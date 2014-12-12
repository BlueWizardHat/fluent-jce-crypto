package net.bluewizardhat.crypto;

import java.security.Key;

/**
 * An encryption engine that combines asymmetric encryption with symmetric encryption.
 * When encrypting it will generate a random symmetric key, encrypt the symmetric key with
 * the asymmetric key and algorithm, and encrypt the actual data with the symmetric key.
 * The format of the encrypted data will then be
 * <ol>
 * <li>4 bytes - length of the encrypted symmetric key
 * <li>x bytes - the encrypted symmetric key
 * <li>y bytes - the encrypted data and initialization vector
 * </ol>
 */
public interface CombinedEncryptionEngine {
	/**
	 * Returns a {@link KeyedFluentEncryptionEngine} that can encrypt and decrypt using the given {@link Key}.
	 *
	 * <p>Note this method does not validate that the key is valid for the implemented algorithm, thus encryption and decryption
	 * may fail even though {@link #withKey} is successful.
	 *
	 * @param asymmetricKey the key to use for encrypting the randomly generated symmetric key
	 * @param symmetricKeyLenght desired length of the symmetric key used to encrypt the actual data
	 */
	public KeyedFluentEncryptionEngine withKey(Key asymmetricKey, int symmetricKeyLenght);
}
