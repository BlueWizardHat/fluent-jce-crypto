package net.bluewizardhat.crypto.exception;

/**
 * Wrapper for various encryption exceptions that should have been runtime exceptions all along.
 */
public class CryptoException extends RuntimeException {
	private static final long serialVersionUID = -4873675726026218829L;

	public CryptoException(String algorithm, String transformation, Exception e) {
		super(algorithm + " (" + transformation + "): " + e.getMessage(), e);
	}

	public CryptoException(String msg, Exception e) {
		super(msg + ": " + e.getMessage(), e);
	}

	public CryptoException(String msg) {
		super(msg);
	}
}
