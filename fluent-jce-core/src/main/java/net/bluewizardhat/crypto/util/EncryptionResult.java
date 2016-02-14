package net.bluewizardhat.crypto.util;

import java.security.MessageDigest;

/**
 * Wrapper around the result of encrypting some data.
 */
public class EncryptionResult {
	private final byte[] result;
	private final byte[] digest;

	public EncryptionResult(byte[] result, MessageDigest messageDigest) {
		this.result = result;
		this.digest = messageDigest != null ? messageDigest.digest() : null;
	}

	/**
	 * Returns the encrypted data.
	 */
	public byte[] getResult() {
		return result;
	}

	/**
	 * Returns a message digest of the encrypted data or <code>null</code>.
	 */
	public byte[] getDigest() {
		return digest;
	}
}
