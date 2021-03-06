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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import net.bluewizardhat.crypto.exception.BadHmacException;

/**
 * An encryption engine that has been initialized to use a given {@link Key} or password to encrypt and decrypt.
 *
 * @see BaseFluentEncryptionEngine#withKey(java.security.Key)
 * @see SymmetricEncryptionEngine#withPassword(String, int)
 * @see CombinedEncryptionEngine#withKey(Key, int)
 */
public interface KeyedFluentEncryptionEngine {
	/**
	 * Encrypts some data and returns the result. Note if the input data is large this operation may require a large amount of
	 * memory, in such case you may be better of using {@link #createEncryptingOutputStream(OutputStream)}.
	 */
	public byte[] encryptData(byte[] data);

	/**
	 * Decrypt some data and returns the result. Note if the input data is large this operation may require a large amount of
	 * memory, in such case you may be better of using {@link #createEncryptingOutputStream(OutputStream)}.
	 * This method may throw a {@link BadHmacException} if decrypting with HMAC using the wrong key, password or algorithm.
	 */
	public byte[] decryptData(byte[] data);

	/**
	 * Creates a {@link CipherOutputStream} that when written to will encrypt the given data and write the encrypted data to
	 * <code>target</code>. The {@link CipherOutputStream} should be flushed before closing or some data may not have been encrypted
	 * and written.
	 * Make sure that you do not write to the target OutputStream yourself after calling this method or you may not be able to
	 * decrypt the data again.
	 */
	public CipherOutputStream createEncryptingOutputStream(OutputStream target) throws IOException;

	/**
	 * Creates a {@link CipherInputStream} that will read encrypted data from <code>source</code> and decrypt it.
	 * This method may throw a {@link BadHmacException} if decrypting with HMAC using the wrong key, password or algorithm.
	 * Make sure that you do not read from the source InputStream yourself after calling this method or you may not be able to
	 * decrypt the data.
	 */
	public CipherInputStream createDecryptingInputStream(InputStream source) throws IOException;
}
