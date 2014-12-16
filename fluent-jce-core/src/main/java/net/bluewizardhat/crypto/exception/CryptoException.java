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

/**
 * Wrapper for various encryption exceptions that should have been runtime exceptions all along.
 */
public class CryptoException extends RuntimeException {
	private static final long serialVersionUID = -4873675726026218829L;

	public CryptoException(String algorithm, String transformation, Exception e) {
		super(algorithm + " (" + transformation + "): " + e.getMessage(), e);
	}

	public CryptoException(String msg, Exception e) {
		super(msg + ": " + e.getMessage(), e);
	}

	public CryptoException(String msg) {
		super(msg);
	}
}
