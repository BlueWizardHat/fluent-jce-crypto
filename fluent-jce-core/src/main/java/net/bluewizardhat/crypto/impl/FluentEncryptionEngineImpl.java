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

package net.bluewizardhat.crypto.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.DigestOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import net.bluewizardhat.crypto.AsymmetricEncryptionEngine;
import net.bluewizardhat.crypto.BaseFluentEncryptionEngine;
import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;
import net.bluewizardhat.crypto.exception.BadHmacException;
import net.bluewizardhat.crypto.exception.CryptoException;
import net.bluewizardhat.crypto.securerandom.SecureRandomSupplier;
import net.bluewizardhat.crypto.securerandom.StaticCountingSecureRandomSupplier;
import net.bluewizardhat.crypto.util.EncryptionOutputStream;
import net.bluewizardhat.crypto.util.EncryptionResult;

/**
 * Implementation of an {@link BaseFluentEncryptionEngine}.
 * This class and subclasses are thread-safe and immutable.
 */
public class FluentEncryptionEngineImpl implements SymmetricEncryptionEngine, AsymmetricEncryptionEngine {
	// Salt size in bytes for salting passwords
	private static final int PWD_SALT_SIZE = 8;

	// Minimum generated initialization vector to have data for an HMAC
	private static final int MIN_GENERATED_IV_SIZE = 16;

	private static final Charset UTF_8 = Charset.forName("UTF-8");

	// One empty array to rule them all.
	private static final byte[] EMPTY_BYTES = new byte[0];

	private final String algorithm;
	private final String transformation;
	private final int cipherIvSize;
	private final boolean useHmac;
	private final int generatedIvSize;
	private final String provider;

	private SecureRandomSupplier secureRandomSupplier = StaticCountingSecureRandomSupplier.getInstance();

	/**
	 * Instantiates a new {@link SymmetricEncryptionEngine}
	 * @param algorithm algorithm, for example "AES"
	 * @param transformation transformation to use, for example "AES/CFB/PKCS5Padding"
	 * @param cipherIvSize the size of the initialization vector in bytes or 0 if the chosen mode does not use an iv
	 */
	public static SymmetricEncryptionEngine getSymmetricEncryptionEngine(String algorithm, String transformation, int cipherIvSize) {
		return new FluentEncryptionEngineImpl(algorithm, transformation, cipherIvSize, false, null);
	}

	/**
	 * Instantiates a new {@link SymmetricEncryptionEngine}
	 * @param algorithm algorithm, for example "AES"
	 * @param transformation transformation to use, for example "AES/CFB/PKCS5Padding"
	 * @param cipherIvSize the size of the initialization vector in bytes or 0 if the chosen mode does not use an iv
	 * @param provider name of the provider to use
	 */
	public static SymmetricEncryptionEngine getSymmetricEncryptionEngine(String algorithm, String transformation, int cipherIvSize,
			String provider) {
		return new FluentEncryptionEngineImpl(algorithm, transformation, cipherIvSize, false, provider);
	}

	/**
	 * Instantiates a new {@link AsymmetricEncryptionEngine}
	 * @param algorithm algorithm, for example "RSA"
	 * @param transformation transformation to use, for example "RSA/ECB/PKCS1Padding"
	 */
	public static AsymmetricEncryptionEngine getAsymmetricEncryptionEngine(String algorithm, String transformation) {
		return new FluentEncryptionEngineImpl(algorithm, transformation, 0, false, null);
	}

	/**
	 * Instantiates a new {@link AsymmetricEncryptionEngine}
	 * @param algorithm algorithm, for example "RSA"
	 * @param transformation transformation to use, for example "RSA/ECB/PKCS1Padding"
	 * @param provider name of the provider to use
	 */
	public static AsymmetricEncryptionEngine getAsymmetricEncryptionEngine(String algorithm, String transformation, String provider) {
		return new FluentEncryptionEngineImpl(algorithm, transformation, 0, false, provider);
	}

	private FluentEncryptionEngineImpl(String algorithm, String transformation, int cipherIvSize, boolean useHmac, String provider) {
		if (algorithm == null) {
			throw new IllegalArgumentException("algorithm may not be null");
		}
		if (transformation == null) {
			throw new IllegalArgumentException("transformation may not be null");
		}
		if (cipherIvSize < 0) {
			throw new IllegalArgumentException("ivSize may not be less than zero");
		}

		this.algorithm = algorithm;
		this.transformation = transformation;
		this.cipherIvSize = cipherIvSize;
		this.useHmac = useHmac;
		this.provider = provider;
		generatedIvSize = useHmac ? Math.max(cipherIvSize, MIN_GENERATED_IV_SIZE) : cipherIvSize;
	}

	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	@Override
	public String getTransformation() {
		return transformation;
	}

	@Override
	public KeyedFluentEncryptionEngine withPassword(String password, int keyLength) {
		return new KeyedFluentEncryptionEngineWithPassword(password, keyLength);
	}

	@Override
	public KeyedFluentEncryptionEngine withKey(Key key) {
		return new KeyedFluentEncryptionEngineWithKey(key);
	}

	@Override
	public SymmetricEncryptionEngine withHmac() {
		return useHmac ? this : new FluentEncryptionEngineImpl(algorithm, transformation, cipherIvSize, true, provider);
	}

	private static class SaltedKey {
		final Key key;
		final byte[] salt;

		SaltedKey(Key key, byte[] salt) {
			this.key = key;
			this.salt = salt;
		}
	}

	private class Iv {
		final byte[] iv;

		Iv() {
			iv = (generatedIvSize != 0) ? new byte[generatedIvSize] : EMPTY_BYTES;
			secureRandomSupplier.currentSecureRandom().nextBytes(iv);
		}

		Iv(byte[] iv) {
			this.iv = iv;
		}

		IvParameterSpec getIvParameterSpec() {
			if (cipherIvSize == 0) {
				return null;
			}
			if (cipherIvSize < generatedIvSize) {
				return new IvParameterSpec(Arrays.copyOf(iv, cipherIvSize));
			}
			return new IvParameterSpec(iv);
		}
	}

	private abstract class BaseKeyedFluentEncryptionEngine extends BaseKeyedEncryptionEngineImpl implements KeyedFluentEncryptionEngine {
		abstract int getSaltSize();
		abstract SaltedKey getSaltedKeyForEncryption();
		abstract SaltedKey getSaltedKeyWithSalt(byte[] salt);

		@Override
		public EncryptionResult encryptData(byte[] data, MessageDigest messageDigest) {
			try {
				SaltedKey saltedKey = getSaltedKeyForEncryption();
				Iv iv = new Iv();

				// calculate the hmac
				byte[] hmac = calcHmac(saltedKey, iv);

				// get the cipher
				Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, saltedKey.key, iv);

				// encrypt
				byte[] encrypted = cipher.doFinal(data);

				// return salt, initialization vector and hmac with the encrypted data
				byte[] returnData = ByteBuffer
						.allocate(saltedKey.salt.length + iv.iv.length + hmac.length + encrypted.length)
						.put(saltedKey.salt).put(iv.iv).put(hmac).put(encrypted)
						.array();
				if (messageDigest != null) {
					messageDigest.reset();
					messageDigest.update(returnData);
				}
				return new EncryptionResult(returnData, messageDigest);
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new CryptoException(algorithm, transformation, e);
			}
		}

		@Override
		public byte[] decryptData(byte[] data) {
			try {
				int saltSize = getSaltSize();

				// Sanity check
				if (data.length < saltSize + generatedIvSize) {
					throw new IllegalArgumentException("Cannot decrypt, not enough data");
				}

				// extract the salt and initialization vector
				byte[] salt = Arrays.copyOf(data, saltSize);
				Iv iv = new Iv(Arrays.copyOfRange(data, saltSize, saltSize + generatedIvSize));
				SaltedKey saltedKey = getSaltedKeyWithSalt(salt);

				// Calc the hmac
				byte[] hmac = calcHmac(saltedKey, iv);

				// Another sanity check
				if (data.length < saltSize + generatedIvSize + hmac.length) {
					throw new IllegalArgumentException("Cannot decrypt, not enough data");
				}

				// verify the hmac
				byte[] sourceHmac = Arrays.copyOfRange(data, saltSize + generatedIvSize, saltSize + generatedIvSize + hmac.length);
				if (!Arrays.equals(hmac, sourceHmac)) {
					throw new BadHmacException("Cannot decrypt, HMAC does not match");
				}

				// get the cipher
				Cipher cipher = getCipher(Cipher.DECRYPT_MODE, saltedKey.key, iv);

				// decrypt and return result
				return cipher.doFinal(data, generatedIvSize + saltSize + hmac.length,
						data.length - generatedIvSize - saltSize - hmac.length);
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new CryptoException(algorithm, transformation, e);
			}
		}

		@Override
		public EncryptionOutputStream createEncryptingOutputStream(OutputStream target, MessageDigest messageDigest) throws IOException {
			Iv iv = new Iv();
			SaltedKey saltedKey = getSaltedKeyForEncryption();
			byte[] hmac = calcHmac(saltedKey, iv);

			// get the cipher
			Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, saltedKey.key, iv);

			// Wrap target in a DigestOutputStream if messageDigest is given
			if (messageDigest != null) {
				messageDigest.reset();
				DigestOutputStream dos = new DigestOutputStream(target, messageDigest);
				target = dos;
			}

			// write salt, iv and hmac
			target.write(saltedKey.salt);
			target.write(iv.iv);
			target.write(hmac);

			// Return a usable OutputStream
			return new EncryptionOutputStream(new CipherOutputStream(target, cipher), messageDigest);
		}

		@Override
		public CipherInputStream createDecryptingInputStream(InputStream source) throws IOException {
			int saltSize = getSaltSize();

			// extract the salt and initialization vector
			byte[] ivAndSalt = new byte[generatedIvSize + saltSize];
			int read = source.read(ivAndSalt);

			if (read < ivAndSalt.length) {
				throw new IllegalArgumentException("Cannot read encrypted data from the given InputStream, not enough data");
			}

			byte[] salt = Arrays.copyOf(ivAndSalt, saltSize);
			Iv iv = new Iv(Arrays.copyOfRange(ivAndSalt, saltSize, saltSize + generatedIvSize));
			SaltedKey saltedKey = getSaltedKeyWithSalt(salt);

			// verify the hmac
			byte[] hmac = calcHmac(saltedKey, iv);
			byte[] sourceHmac = new byte[hmac.length];
			read = source.read(sourceHmac);

			if (read < hmac.length) {
				throw new IllegalArgumentException("Cannot read encrypted data from the given InputStream, not enough data");
			}

			if (!Arrays.equals(hmac, sourceHmac)) {
				throw new BadHmacException("Cannot decrypt, HMAC does not match");
			}

			// get the cipher
			Cipher cipher = getCipher(Cipher.DECRYPT_MODE, saltedKey.key, iv);

			// Return a usable InputStream
			return new CipherInputStream(source, cipher);
		}

		private Cipher getCipher(int mode, Key key, Iv iv) {
			try {
				Cipher cipher = (provider == null) ? Cipher.getInstance(transformation) : Cipher.getInstance(transformation, provider);
				cipher.init(mode, key, iv.getIvParameterSpec());
				return cipher;
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
					| NoSuchProviderException e) {
				throw new CryptoException(algorithm, transformation, e);
			}
		}

		private byte[] calcHmac(SaltedKey saltedKey, Iv iv) {
			if (!useHmac || !(saltedKey.key instanceof SecretKey)) {
				return EMPTY_BYTES;
			}

			try {
				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(new SecretKeySpec(saltedKey.key.getEncoded(), "HmacSHA256"));
				mac.update(transformation.getBytes(UTF_8));
				mac.update(saltedKey.salt);
				mac.update(iv.iv);
				return mac.doFinal();
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new CryptoException("Unable to calculate HMAC", e);
			}
		}
	}

	private class KeyedFluentEncryptionEngineWithKey extends BaseKeyedFluentEncryptionEngine {
		private final Key key;

		public KeyedFluentEncryptionEngineWithKey(Key key) {
			if (key == null) {
				throw new IllegalArgumentException("key may not be null");
			}
			this.key = key;
		}

		@Override
		int getSaltSize() {
			return 0;
		}

		@Override
		SaltedKey getSaltedKeyForEncryption() {
			return new SaltedKey(key, EMPTY_BYTES);
		}

		@Override
		SaltedKey getSaltedKeyWithSalt(byte[] salt) {
			return new SaltedKey(key, EMPTY_BYTES);
		}
	}

	private class KeyedFluentEncryptionEngineWithPassword extends BaseKeyedFluentEncryptionEngine {
		private final String password;
		private final int keyLength;

		public KeyedFluentEncryptionEngineWithPassword(String password, int keyLength) {
			if (password == null || keyLength <= 0) {
				throw new IllegalArgumentException("password must be non-null and keyLength must be positive");
			}
			this.password = password;
			this.keyLength = keyLength;
		}

		@Override
		int getSaltSize() {
			return PWD_SALT_SIZE;
		}

		@Override
		SaltedKey getSaltedKeyForEncryption() {
			byte[] salt = new byte[PWD_SALT_SIZE];
			secureRandomSupplier.currentSecureRandom().nextBytes(salt);
			return getSaltedKeyWithSalt(salt);
		}

		@Override
		SaltedKey getSaltedKeyWithSalt(byte[] salt) {
			try {
				PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, keyLength);
				SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				SecretKey tmp = secretKeyFactory.generateSecret(pbeKeySpec);
				return new SaltedKey(new SecretKeySpec(tmp.getEncoded(), algorithm), salt);
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new CryptoException(algorithm, transformation, e);
			}
		}
	}
}
