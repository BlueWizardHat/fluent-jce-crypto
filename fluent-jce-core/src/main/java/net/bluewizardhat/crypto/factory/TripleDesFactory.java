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
 * Example of a factory for encryption with TripleDES (also known as 3DES or DESede).
 */
public class TripleDesFactory {

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements TripleDES in CTR mode
	 * with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTripleDesCtr() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("DESede", "DESede/CTR/PKCS5Padding", 8);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements TripleDES in CBC mode
	 * with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTripleDesCbc() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("DESede", "DESede/CBC/PKCS5Padding", 8);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements TripleDES in CFB mode
	 * with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTripleDesCfb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("DESede", "DESede/CFB/PKCS5Padding", 8);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements TripleDES in ECB mode
	 * with PKCS5 padding.
	 * ECB is the least safe mode for TripleDES.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTripleDesEcb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("DESede", "DESede/ECB/PKCS5Padding", 0);
	}

	/**
	 * Generate a random {@link SecretKey} that can be used with the algorithm implemented by this factory.
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(int keyLength) {
		return KeyGenerator.generateKey("DESede", keyLength);
	}
}
