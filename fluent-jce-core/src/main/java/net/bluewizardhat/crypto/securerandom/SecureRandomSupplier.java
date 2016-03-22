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

package net.bluewizardhat.crypto.securerandom;

import java.security.SecureRandom;

/**
 * A supplier of {@link SecureRandom}s.
 *
 * <p>It is good security practice to re-seed {@link SecureRandom}s once in a while. Implementations of this interface
 * should therefore re-seed the {@link SecureRandom} produced.
 */
public interface SecureRandomSupplier {
	/**
	 * Returns the current SecureRandom instance for the thread.
	 */
	public SecureRandom currentSecureRandom();
}
