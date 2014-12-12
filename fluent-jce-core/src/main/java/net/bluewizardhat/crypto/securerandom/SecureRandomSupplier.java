package net.bluewizardhat.crypto.securerandom;

import java.security.SecureRandom;

/**
 * A supplier of {@link SecureRandom}s.
 *
 * <p>It is good security practice to re-seed {@link SecureRandom}s once in a while. Implementations of this interface
 * should therefore re-seed the {@link SecureRandom} produced.
 */
public interface SecureRandomSupplier {
	/**
	 * Returns the current SecureRandom instance for the thread.
	 */
	public SecureRandom currentSecureRandom();
}
