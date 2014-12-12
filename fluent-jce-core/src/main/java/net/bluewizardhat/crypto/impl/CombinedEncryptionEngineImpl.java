package net.bluewizardhat.crypto.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Key;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.bluewizardhat.crypto.AsymmetricEncryptionEngine;
import net.bluewizardhat.crypto.CombinedEncryptionEngine;
import net.bluewizardhat.crypto.KeyGenerator;
import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.SymmetricEncryptionEngine;

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
 *
 * This class and subclasses are thread-safe and immutable.
 */
public class CombinedEncryptionEngineImpl implements CombinedEncryptionEngine {

	private AsymmetricEncryptionEngine asymmetricEngine;
	private SymmetricEncryptionEngine symmetricEngine;

	/**
	 * Creates a CombinedEncryptionEngineImpl that combines the use of the given encryption engines.
	 * @param asymmetricEngine
	 * @param symmetricEngine
	 */
	public CombinedEncryptionEngineImpl(AsymmetricEncryptionEngine asymmetricEngine, SymmetricEncryptionEngine symmetricEngine) {
		this.asymmetricEngine = asymmetricEngine;
		this.symmetricEngine = symmetricEngine;
	}

	@Override
	public KeyedFluentEncryptionEngine withKey(Key asymmetricKey, int symmetricKeyLenght) {
		return new KeyedCombinedEngine(asymmetricKey, symmetricKeyLenght);
	}

	private class KeyedCombinedEngine implements KeyedFluentEncryptionEngine {
		private final Key asymmetricKey;
		private final int symmetricKeyLenght;

		public KeyedCombinedEngine(Key asymmetricKey, int symmetricKeyLenght) {
			this.asymmetricKey = asymmetricKey;
			this.symmetricKeyLenght = symmetricKeyLenght;
		}

		@Override
		public byte[] encryptData(byte[] data) {
			// Generate a random SecretKey for data encryption
			SecretKey symmetricKey = KeyGenerator.generateKey(symmetricEngine.getAlgorithm(), symmetricKeyLenght);

			// Encrypt the symmetric key
			byte[] encryptedSymmetricKey = asymmetricEngine.withKey(asymmetricKey).encryptData(symmetricKey.getEncoded());

			// Encrypt the actual data
			byte[] encryptedData = symmetricEngine.withKey(symmetricKey).encryptData(data);

			// Return the result
			return ByteBuffer.allocate(4 + encryptedSymmetricKey.length + encryptedData.length)
					.putInt(encryptedSymmetricKey.length)
					.put(encryptedSymmetricKey)
					.put(encryptedData)
					.array();
		}

		@Override
		public byte[] decryptData(byte[] data) {
			ByteBuffer dataBuffer = ByteBuffer.wrap(data);
			
			// Extract the encrypted symmetric key
			int encryptedSymmetricKeyLength = dataBuffer.getInt();
			byte[] encryptedSymmetricKey = new byte[encryptedSymmetricKeyLength];
			dataBuffer.get(encryptedSymmetricKey);

			// Decrypt the symmetric key and create a usable SecretKey
			SecretKey symmetricKey = new SecretKeySpec(
					asymmetricEngine.withKey(asymmetricKey).decryptData(encryptedSymmetricKey),
					symmetricEngine.getAlgorithm());

			// Extract encrypted data
			byte[] encryptedData = new byte[dataBuffer.remaining()];
			dataBuffer.get(encryptedData, 0, encryptedData.length);

			// Decrypt and return the result
			return symmetricEngine.withKey(symmetricKey).decryptData(encryptedData);
		}

		@Override
		public CipherOutputStream createEncryptingOutputStream(OutputStream target) throws IOException {
			// Generate a random SecretKey for data encryption
			SecretKey symmetricKey = KeyGenerator.generateKey(symmetricEngine.getAlgorithm(), symmetricKeyLenght);

			// Encrypt the symmetric key
			byte[] encryptedSymmetricKey = asymmetricEngine.withKey(asymmetricKey).encryptData(symmetricKey.getEncoded());

			// write out the encrypted symmetric key and it's length
			target.write(ByteBuffer.allocate(4 + encryptedSymmetricKey.length)
					.putInt(encryptedSymmetricKey.length)
					.put(encryptedSymmetricKey)
					.array());

			// Returns the encrypting CipherOutputStream
			return symmetricEngine.withKey(symmetricKey).createEncryptingOutputStream(target);
		}

		@Override
		public CipherInputStream createDecryptingInputStream(InputStream source) throws IOException {
			// Extract the encrypted symmetric key
			byte[] encryptedSymmetricKeyLengthBytes = readBytes(source, 4);
			int encryptedSymmetricKeyLength = ByteBuffer.wrap(encryptedSymmetricKeyLengthBytes).getInt();
			byte[] encryptedSymmetricKey = readBytes(source, encryptedSymmetricKeyLength);
			
			// Decrypt the symmetric key and create a usable SecretKey
			SecretKey symmetricKey = new SecretKeySpec(
					asymmetricEngine.withKey(asymmetricKey).decryptData(encryptedSymmetricKey),
					symmetricEngine.getAlgorithm());

			// Returns the decrypting CipherInputStream
			return symmetricEngine.withKey(symmetricKey).createDecryptingInputStream(source);
		}
		
		private byte[] readBytes(InputStream source, int length) throws IOException {
			byte[] data = new byte[length];
			int read = source.read(data);

			if (read < length) {
				throw new IllegalArgumentException("Cannot read encrypted data from the given InputStream, not enough data");
			}
			return data;
		}
		
	}
}
