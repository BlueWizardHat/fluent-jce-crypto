A wrapper for Java Cryptography Extension (JCE) with a fluent syntax
=========================================================================

This small library implements a fluent style wrapper around Java Cryptography Extension (JCE). Hopefully making it easy to implement encryption in java applications in a proper way.

With this library you can encrypt some data like this

	byte[] encrypted =
		AesFactory
			.usingAesCfb()
			.withPassword("secret", 256)
			.encryptData(data);

Or write data encrypted to a file

		try (FileOutputStream fileOut = new FileOutputStream("file");
				OutputStream out = AesFactory
					.usingAesCfb()
					.withPassword("secret", 256)
					.createEncryptingOutputStream(fileOut)) {
			out.write(data);
			out.flush();
		}

And the library will take care of all the tedious details about setting up the cipher correctly, salting the password, generating a proper initialization vector and all that.

Disclaimer: I am by no means an cryptography expert, and this library does not contain any encryption algorithm implementations, it is just a wrapper around JCE. I just saw a need for a simpler API for the sometimes rather cryptic API that is part of standard java.

Note: If you want so use strong encryption with Oracle's JVM you will need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files for your JDK/JRE.


# Features

* Fluent API - Easy to read and easy to write
* Always salts passwords - Encrypt the same data multiple times using password encryption and you will get different results each time
* Always generates a random IV for any non-ECB mode - Encrypt the same data multiple times using any non-ECB mode and you will get different results each time
* Easy to expand with other algorithms should you need to


# License

Copyright (C) 2014 BlueWizardHat

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

