package net.bluewizardhat.crypto;

import java.security.Key;

import net.bluewizardhat.crypto.exception.BadHmacException;

/**
 * Interface defining the methods available for a symmetric cipher.
 */
public interface SymmetricEncryptionEngine extends BaseFluentEncryptionEngine {
	/**
	 * Returns a {@link KeyedFluentEncryptionEngine} that can encrypt and decrypt using the given password.
	 *
	 * <p>Note that for decrypting both password AND keyLength must be the same as that which was used for encryption.
	 * The password will be salted before encryption, a different salt will be generated every time something is encrypted.
	 *
	 * <p>Note this method does not validate that the keyLength is valid for the implemented algorithm, thus encryption and decryption
	 * may fail even though {@link #withPassword} is successful.
	 */
	public KeyedFluentEncryptionEngine withPassword(String password, int keyLength);

	/**
	 * <p>When encrypting using a password or a {@link Key} that is an instance of SecretKey the {@link BaseFluentEncryptionEngine}
	 * returned from this method will calculate an HMAC and include it in the encrypted data. On decryption the same HMAC
	 * is checked and a {@link BadHmacException} is thrown if the HMAC does not match. This is to be able to detect if the
	 * key or password used when decrypting matches the key or password that was used to encrypt. By default this does not
	 * happen, use this method if you want the HMAC check.
	 *
	 * <p>Three things to be aware of:
	 * <ol>
	 * <li>This method does not alter the internal state of the instance it is called on, the original instance
	 * will still not perform an HMAC check, so use the instance returned by this method instead of the original instance
	 * if you want the HMAC.
	 * <li>You will need to use the same setting when decrypting that was used when encrypting. Thus if you encrypt
	 * using enabled HMAC then you will also need to decrypt using enabled HMAC, and if you encrypt
	 * using disabled HMAC then you will also need to decrypt using disabled HMAC. In short: Decide how you want to use this
	 * framework and stick to that decision.
	 * <li>When using the wrong key or password to decrypt without HMAC validation you may still get an exception but it
	 * may be somewhat more cryptic, and won't be a {@link BadHmacException}.
	 * </ol>
	 *
	 */
	public SymmetricEncryptionEngine withHmac();
}
