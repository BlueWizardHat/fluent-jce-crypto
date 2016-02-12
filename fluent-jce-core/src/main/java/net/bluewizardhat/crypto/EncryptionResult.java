package net.bluewizardhat.crypto;

import java.security.MessageDigest;

public class EncryptionResult<R> {
	R result;
	MessageDigest digester;

	public EncryptionResult(R result, MessageDigest digester) {
		this.result = result;
		this.digester = digester;
	}

	public R getResult() {
		return result;
	}

	public byte[] getDigest() {
		return digester.digest();
	}
}
