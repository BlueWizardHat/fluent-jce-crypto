package net.bluewizardhat.crypto.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

import javax.crypto.CipherOutputStream;

import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;

/**
 * Wrapper around a CipherOutputStream and the MessageDigest used to calculate the digest of encrypted data.
 */
public class EncryptionOutputStream extends FilterOutputStream {
	private final CipherOutputStream out;
	private final MessageDigest messageDigest;

	public EncryptionOutputStream(CipherOutputStream out, MessageDigest messageDigest) {
		super(out);
		this.out = out;
		this.messageDigest = messageDigest;
	}

	/**
	 * Return the MessageDigest used to calculate a digest of the encrypted data. After the stream has been closed
	 * one can call the {@linkplain MessageDigest#digest()} method of the MessageDigest to get the digest.
	 * If {@linkplain KeyedFluentEncryptionEngine#createEncryptingOutputStream(OutputStream, MessageDigest)} was
	 * called with a <code>null</code> MessageDigest, then this method will return <code>null</code>.
	 */
	public MessageDigest getMessageDigest() {
		return messageDigest;
	}

	// For some reason FilterOutputStream overrides this to a much less efficient version, so lets fix this
	/**
	 * Writes len bytes from the specified byte array starting at offset off to this output stream.
	 * @see OutputStream#write(byte[], int, int)
	 */
	@Override
	public void write(byte b[], int off, int len) throws IOException {
		out.write(b, off, len);
	}
}
