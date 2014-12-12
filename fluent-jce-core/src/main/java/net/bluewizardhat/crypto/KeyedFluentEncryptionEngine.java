package net.bluewizardhat.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import net.bluewizardhat.crypto.exception.BadHmacException;

/**
 * An encryption engine that has been initialized to use a given {@link Key} or password to encrypt and decrypt.
 *
 * @see BaseFluentEncryptionEngine#withKey(java.security.Key)
 * @see SymmetricEncryptionEngine#withPassword(String, int)
 * @see CombinedEncryptionEngine#withKey(Key, int)
 */
public interface KeyedFluentEncryptionEngine {
	/**
	 * Encrypts some data and returns the result. Note if the input data is large this operation may require a large amount of
	 * memory, in such case you may be better of using {@link #createEncryptingOutputStream(OutputStream)}.
	 */
	public byte[] encryptData(byte[] data);

	/**
	 * Decrypt some data and returns the result. Note if the input data is large this operation may require a large amount of
	 * memory, in such case you may be better of using {@link #createEncryptingOutputStream(OutputStream)}.
	 * This method may throw a {@link BadHmacException} if decrypting with HMAC using the wrong key, password or algorithm.
	 */
	public byte[] decryptData(byte[] data);

	/**
	 * Creates a {@link CipherOutputStream} that when written to will encrypt the given data and write the encrypted data to
	 * <code>target</code>. The {@link CipherOutputStream} should be flushed before closing or some data may not have been encrypted
	 * and written.
	 */
	public CipherOutputStream createEncryptingOutputStream(OutputStream target) throws IOException;

	/**
	 * Creates a {@link CipherInputStream} that will read encrypted data from <code>source</code> and decrypt it.
	 * This method may throw a {@link BadHmacException} if decrypting with HMAC using the wrong key, password or algorithm.
	 */
	public CipherInputStream createDecryptingInputStream(InputStream source) throws IOException;
}