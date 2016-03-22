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

package net.bluewizardhat.crypto;

import java.security.Key;

/**
 * Base interface for a encryption engine with a fluent API.
 *
 * An encryption engine with a fluent API. An example of usage could be something like:
 * <code><pre>
 * byte[] encryptedData = AesFactory.usingAesCbc().withKey(key).encryptData(rawData);
 * </pre></code>
 */
public interface BaseFluentEncryptionEngine {
	/**
	 * Returns a {@link KeyedFluentEncryptionEngine} that can encrypt and decrypt using the given {@link Key}.
	 *
	 * <p>Note this method does not validate that the key is valid for the implemented algorithm, thus encryption and decryption
	 * may fail even though {@link #withKey} is successful.
	 */
	public KeyedFluentEncryptionEngine withKey(Key key);

	/**
	 * Returns the algorithm implemented by this {@link BaseFluentEncryptionEngine}.
	 */
	public String getAlgorithm();

	/**
	 * Returns the transformation implemented by this {@link BaseFluentEncryptionEngine}.
	 */
	public String getTransformation();
}
