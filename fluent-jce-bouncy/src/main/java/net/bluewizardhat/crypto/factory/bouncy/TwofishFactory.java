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

package net.bluewizardhat.crypto.factory.bouncy;

import java.security.Security;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;
import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.impl.FluentEncryptionEngineImpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Example of a factory utilizing the Bounce Castle providers for encryption with Twofish.
 * See also <a href="http://www.bouncycastle.org/">The Legion of the Bouncy Castle</a> website.
 */
public class TwofishFactory {

	/**
	 * Twofish is not part of standard Java, so we make sure to initialize the provider from bouncy castle.
	 */
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Twofish in CTR mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTwofishCtr() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Twofish", "Twofish/CTR/PKCS5Padding", 16,
				BouncyCastleProvider.PROVIDER_NAME);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Twofish in CFB mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTwofishCfb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Twofish", "Twofish/CFB/PKCS5Padding", 16,
				BouncyCastleProvider.PROVIDER_NAME);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Twofish in CBC mode with PKCS5 padding.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTwofishCbc() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Twofish", "Twofish/CBC/PKCS5Padding", 16,
				BouncyCastleProvider.PROVIDER_NAME);
	}

	/**
	 * Returns an {@link SymmetricEncryptionEngine} that implements Twofish in ECB mode with PKCS5 padding.
	 * ECB is the least safe mode for Twofish.
	 * The {@link SymmetricEncryptionEngine} returned by this method is thread-safe.
	 */
	public static SymmetricEncryptionEngine usingTwofishEcb() {
		return FluentEncryptionEngineImpl.getSymmetricEncryptionEngine("Twofish", "Twofish/ECB/PKCS5Padding", 0,
				BouncyCastleProvider.PROVIDER_NAME);
	}

	/**
	 * Generate a random {@link SecretKey} that can be used with the algorithm implemented by this factory.
	 * Throws {@link CryptoException} if a key could not be generated.
	 */
	public static SecretKey generateKey(int keyLength) {
		return KeyGenerator.generateKey("Twofish", keyLength);
	}
}
