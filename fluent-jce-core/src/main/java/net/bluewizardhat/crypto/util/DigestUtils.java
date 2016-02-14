package net.bluewizardhat.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestUtils {
	/**
	 * Utility class
	 */
	private DigestUtils() {
	}

	/**
	 * Returns a MessageDigest for calculating SHA-256
	 */
	public static MessageDigest sha256MessageDigest() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Reads the source InputStream and calculates it's digest. The source will not be closed by this method.
	 *
	 * <p>Note that after this call the InputStream will be completely read. Unless the source can be reset and read again
	 * the data read from it will be lost.
	 */
	public static byte[] calcDigest(InputStream source, MessageDigest messageDigest) throws IOException {
		messageDigest.reset();
		byte[] buf = new byte[4096];
		while (true) {
			int read = source.read(buf);
			if (read == -1) {
				break;
			}
			messageDigest.update(buf, 0, read);
		}
		return messageDigest.digest();
	}
}
