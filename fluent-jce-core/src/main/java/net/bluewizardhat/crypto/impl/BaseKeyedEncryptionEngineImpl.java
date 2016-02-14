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
