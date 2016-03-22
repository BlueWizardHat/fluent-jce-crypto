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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestUtils {
	/**
	 * Utility class
	 */
	private DigestUtils() {
	}

	/**
	 * Returns a MessageDigest for calculating SHA-256
	 */
	public static MessageDigest sha256MessageDigest() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Reads the source InputStream and calculates it's digest. The source will not be closed by this method.
	 *
	 * <p>Note that after this call the InputStream will be completely read. Unless the source can be reset and read again
	 * the data read from it will be lost.
	 */
	public static byte[] calcDigest(InputStream source, MessageDigest messageDigest) throws IOException {
		messageDigest.reset();
		byte[] buf = new byte[4096];
		while (true) {
			int read = source.read(buf);
			if (read == -1) {
				break;
			}
			messageDigest.update(buf, 0, read);
		}
		return messageDigest.digest();
	}
}
