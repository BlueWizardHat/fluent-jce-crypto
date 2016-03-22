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

package net.bluewizardhat.crypto.impl;

import java.io.IOException;
import java.io.OutputStream;

import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.util.DigestUtils;
import net.bluewizardhat.crypto.util.EncryptionOutputStream;
import net.bluewizardhat.crypto.util.EncryptionResult;

public abstract class BaseKeyedEncryptionEngineImpl implements KeyedFluentEncryptionEngine {
	@Override
	public final EncryptionResult encryptData(byte[] data) {
		return encryptData(data, DigestUtils.sha256MessageDigest());
	}

	@Override
	public final EncryptionOutputStream createEncryptingOutputStream(OutputStream target) throws IOException {
		return createEncryptingOutputStream(target, DigestUtils.sha256MessageDigest());
	}
}
