/*
 * Copyright (C) 2014-2016 BlueWizardHat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bluewizardhat.crypto.securerandom;

import java.security.SecureRandom;

/**
 * A supplier of {@link SecureRandom}s in which a single {@link SecureRandom} is shared by all {@link Thread}s
 * in the application. Since {@link SecureRandom} is itself thread-safe this is safe to do.
 *
 * <p>Instantiating new {@link SecureRandom}s every time we need random data would always produce the highest
 * degree of randomness since it would be newly seeded every time. However since seeding and re-seeding can be quite
 * expensive always instantiating new {@link SecureRandom}s can be very bad for performance. However always using
 * the same {@link SecureRandom} can in long running applications degrade the quality of randomness (depending
 * on the systems default PRNG). Therefore re-using a {@link SecureRandom} for a while and then re-seed it and
 * eventually replace it is a much more efficient strategy while at the same time highly secure.
 *
 * <p>For simplicity we do not re-seed an existing {@link SecureRandom}, opting instead to completely replace
 * it with a newly seeded one every time we deem it necessary, which in this implementation is after a number
 * of bytes has been generated OR it has been a set time since the last time is was re-seeded.
 * This is sufficient for most cases.
 */
public class StaticCountingSecureRandomSupplier implements SecureRandomSupplier {
	/**
	 * Re-seed after 128 kb of data has been generated (seems like a fair choice).
	 */
	public static final long DEFAULT_RESEED_MAX_BYTES = 128 * 1024;

	/**
	 * Re-seed at least every 4 hours
	 */
	public static final int DEFAULT_RESEED_MAX_SECONDS = 4 * 60 * 60;

	// Used for auto seeding
	private static final byte[] NO_BYTES = new byte[0];

	private static StaticCountingSecureRandomSupplier INSTANCE = new StaticCountingSecureRandomSupplier();

	/**
	 * Special subclass of SecureRandom that counts the number of bytes generated.
	 */
	private static class CountingSecureRandom extends SecureRandom {
		private static final long serialVersionUID = 8139877477812408893L;

		private final long creationTime = System.currentTimeMillis();
		private long byteCount = 0;

		// SecureRandom is based around nextBytes so this is the only method necessary to override to be
		// able to count the number of bytes generated.
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			super.nextBytes(bytes);
			if (bytes != null) {
				byteCount += bytes.length;
			}
		}

		public synchronized long getByteCount() {
			return byteCount;
		}

		public long getCreationTime() {
			return creationTime;
		}
	}

	// Don't anticipate setting these a lot so not protected by synchronized
	private long reseedMaxBytes;
	private int reseedMaxSeconds;
	private long reseedMaxMillis;

	private CountingSecureRandom currentSecureRandom = null;

	private StaticCountingSecureRandomSupplier() {
		setDefaultReseedSettings();
	}

	/**
	 * Returns the instance of {@link StaticCountingSecureRandomSupplier}
	 */
	public static StaticCountingSecureRandomSupplier getInstance() {
		return INSTANCE;
	}

	@Override
	public synchronized SecureRandom currentSecureRandom() {
		if (currentSecureRandom == null
				|| currentSecureRandom.getByteCount() >= reseedMaxBytes
				|| System.currentTimeMillis() >= currentSecureRandom.getCreationTime() + reseedMaxMillis) {
			// Replace it, we assume the system default random generator is a sane one.
			currentSecureRandom = new CountingSecureRandom();
			// Force the SecureRandom to seed itself immediately, thus avoiding a weakness
			// in SecureRandom where it is possible to set a bad seed before it seeds itself.
			// Once seeded properly any attempts to seed it will only be added to the existing
			// seed, not replace it.
			currentSecureRandom.nextBytes(NO_BYTES);
		}
		return currentSecureRandom;
	}

	/**
	 * Allows you to set a different maximum number of bytes a SecureRandom can generate before re-seeding happens.
	 * Note that re-seeding happens if either maximum number of bytes generated is reached OR the SecureRandom has lived
	 * the maximum number of seconds.
	 */
	public void setReseedMaxBytes(long bytes) {
		if (bytes <= 0) {
			throw new IllegalArgumentException();
		}
		reseedMaxBytes = bytes;
	}

	/**
	 * Allows you to set a different maximum number of seconds for a SecureRandom to live before re-seeding happens.
	 * Note that re-seeding happens if either maximum number of bytes generated is reached OR the SecureRandom has lived
	 * the maximum number of seconds.
	 */
	public void setReseedMaxSeconds(int seconds) {
		if (seconds <= 0) {
			throw new IllegalArgumentException();
		}
		reseedMaxSeconds = seconds;
		reseedMaxMillis = seconds * 1000;
	}

	public long getReseedMaxBytes() {
		return reseedMaxBytes;
	}

	public long getReseedMaxSeconds() {
		return reseedMaxSeconds;
	}

	/**
	 * Resets the re-seeding settings to their defaults (max 128kb data generated and max 4 hours time to live).
	 */
	public void setDefaultReseedSettings() {
		setReseedMaxBytes(DEFAULT_RESEED_MAX_BYTES);
		setReseedMaxSeconds(DEFAULT_RESEED_MAX_SECONDS);
	}
}
