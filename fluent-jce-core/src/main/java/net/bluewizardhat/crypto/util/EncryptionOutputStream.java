package net.bluewizardhat.crypto.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

import javax.crypto.CipherOutputStream;

/**
 * Wrapper around a CipherOutputStream and the MessageDigest used to calculate the digest of encrypted data.
 */
public class EncryptionOutputStream extends FilterOutputStream {
	private final CipherOutputStream out;
	private final MessageDigest digester;

	public EncryptionOutputStream(CipherOutputStream out, MessageDigest digester) {
		super(out);
		this.out = out;
		this.digester = digester;
	}

	/**
	 * Allows you to read the digest of the encrypted data after the stream has been closed, just call the
	 * {@linkplain MessageDigest#digest()} method of the MessageDigest. This method may return null.
	 */
	public MessageDigest getDigester() {
		return digester;
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
