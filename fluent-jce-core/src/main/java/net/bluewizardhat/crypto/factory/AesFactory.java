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

package net.bluewizardhat.crypto.factory;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;
import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.impl.FluentEncryptionEngineImpl;

/**
 * Example of a factory for encryption with AES (Advanced Encryption Standard).
 */
public class AesFactory {

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in CTR mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesCtr() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CTR/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in CFB mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesCfb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CFB/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in CBC mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesCbc() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/CBC/PKCS5Padding", 16);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements AES in ECB mode with PKCS5 padding.
	 * ECB is the least safe mode for AES.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingAesEcb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("AES", "AES/ECB/PKCS5Padding", 0);
	}

	/**
	 * Generate a random {@link SecretKey} that can be used with the algorithm implemented by this factory.
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(int keyLength) {
		return KeyGenerator.generateKey("AES", keyLength);
	}
}
