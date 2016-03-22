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

package net.bluewizardhat.crypto.util;

import java.security.MessageDigest;

/**
 * Wrapper around the result of encrypting some data.
 */
public class EncryptionResult {
	private final byte[] result;
	private final byte[] digest;

	public EncryptionResult(byte[] result, MessageDigest messageDigest) {
		this.result = result;
		this.digest = messageDigest != null ? messageDigest.digest() : null;
	}

	/**
	 * Returns the encrypted data.
	 */
	public byte[] getResult() {
		return result;
	}

	/**
	 * Returns a message digest of the encrypted data or <code>null</code>.
	 */
	public byte[] getDigest() {
		return digest;
	}
}
