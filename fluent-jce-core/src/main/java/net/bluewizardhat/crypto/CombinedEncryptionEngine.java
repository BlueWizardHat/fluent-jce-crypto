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
 * An encryption engine that combines asymmetric encryption with symmetric encryption.
 * When encrypting it will generate a random symmetric key, encrypt the symmetric key with
 * the asymmetric key and algorithm, and encrypt the actual data with the symmetric key.
 * The format of the encrypted data will then be
 * <ol>
 * <li>4 bytes - length of the encrypted symmetric key
 * <li>x bytes - the encrypted symmetric key
 * <li>y bytes - the encrypted data and initialization vector
 * </ol>
 */
public interface CombinedEncryptionEngine {
	/**
	 * Returns a {@link KeyedFluentEncryptionEngine} that can encrypt and decrypt using the given {@link Key}.
	 *
	 * <p>Note this method does not validate that the key is valid for the implemented algorithm, thus encryption and decryption
	 * may fail even though {@link #withKey} is successful.
	 *
	 * @param asymmetricKey the key to use for encrypting the randomly generated symmetric key
	 * @param symmetricKeyLenght desired length of the symmetric key used to encrypt the actual data
	 */
	public KeyedFluentEncryptionEngine withKey(Key asymmetricKey, int symmetricKeyLenght);
}
