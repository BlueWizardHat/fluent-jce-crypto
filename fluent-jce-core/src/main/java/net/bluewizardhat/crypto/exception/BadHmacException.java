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

package net.bluewizardhat.crypto.exception;

import java.security.Key;

import javax.crypto.SecretKey;

import net.bluewizardhat.crypto.BaseFluentEncryptionEngine;

/**
 * Exception indicating that the {@link Key}, password or algorithm used to decrypt was not the same as what was used to encrypt.
 * This can only be detected for symmetric {@link Key}s (ie. {@link Key}s of type {@link SecretKey}) and for passwords and only if
 * {@link BaseFluentEncryptionEngine#withHmac()} is used.
 */
public class BadHmacException extends CryptoException {
	private static final long serialVersionUID = -3202960228008760619L;

	public BadHmacException(String msg) {
		super(msg);
	}
}
