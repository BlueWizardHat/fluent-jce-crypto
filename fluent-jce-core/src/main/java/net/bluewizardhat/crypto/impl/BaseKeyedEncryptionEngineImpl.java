package net.bluewizardhat.crypto.impl;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.CipherOutputStream;

import net.bluewizardhat.crypto.EncryptionResult;
import net.bluewizardhat.crypto.KeyedFluentEncryptionEngine;
import net.bluewizardhat.crypto.exception.CryptoException;

public abstract class BaseKeyedEncryptionEngineImpl implements KeyedFluentEncryptionEngine {
	@Override
	public final EncryptionResult<byte[]> encryptData(byte[] data) {
		try {
			MessageDigest digester = MessageDigest.getInstance("SHA-256");
			return encryptData(data, digester);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e.getMessage(), e);
		}
	}

	@Override
	public final EncryptionResult<CipherOutputStream> createEncryptingOutputStream(OutputStream target) throws IOException {
		try {
			MessageDigest digester = MessageDigest.getInstance("SHA-256");
			return createEncryptingOutputStream(target, digester);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e.getMessage(), e);
		}
	}
}
