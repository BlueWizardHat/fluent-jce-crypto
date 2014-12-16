/*
 * Copyright (C) 2014 BlueWizardHat
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

package net.bluewizardhat.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.securerandom.SecureRandomSupplier;
import net.bluewizardhat.crypto.securerandom.StaticCountingSecureRandomSupplier;

/**
 * Helper class to generate encryption keys.
 */
public class KeyGenerator {
	private static SecureRandomSupplier secureRandomSupplier = StaticCountingSecureRandomSupplier.getInstance();

	/**
	 * Generate a random {@link SecretKey} that can be used with the given algorithm for use with symmetric ciphers such as AES, Blowfish, etc..
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(String algorithm, int keyLength) {
		if (algorithm == null) {
			throw new IllegalArgumentException("algorithm may not be null");
		}
		try {
			javax.crypto.KeyGenerator keyGenerator = javax.crypto.KeyGenerator.getInstance(algorithm);
			keyGenerator.init(keyLength, secureRandomSupplier.currentSecureRandom());
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(algorithm, e);
		}
	}

	/**
	 * Generate a random {@link KeyPair} that can be used with the given algorithm for use with asymmetric ciphers such as RSA, etc..
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static KeyPair generateKeyPair(String algorithm, int keyLength) {
		if (algorithm == null) {
			throw new IllegalArgumentException("algorithm may not be null");
		}
		try {
			java.security.KeyPairGenerator keyGenerator = java.security.KeyPairGenerator.getInstance(algorithm);
			keyGenerator.initialize(keyLength, secureRandomSupplier.currentSecureRandom());
			return keyGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(algorithm, e);
		}
	}
}
