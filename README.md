A wrapper for Java Cryptography Extension (JCE) with a fluent syntax
=========================================================================

This small library implements a fluent style wrapper around Java JCE. Hopefully making it easy to implement encryption in Java applications in a proper way.

With this library you can encrypt some data like this

	byte[] encrypted =
		AesFactory.usingAesCfb()
			.withPassword("secret", 256).encryptData(data);

Or write data encrypted to a file

		try (FileOutputStream fileOut = new FileOutputStream("file");
				OutputStream out = AesFactory.usingAesCfb()
					.withPassword("secret", 256)
					.createEncryptingOutputStream(fileOut)) {
			out.write(data);
			out.flush();
		}

And the library will take care of all the tedious details about setting up the cipher correctly, generating a proper initialization vector and all that.


Disclaimer: I am by no means an cryptography expert, and this library does not contain any encryption algorithm implementations, it is just a wrapper around JCE. I just saw a need for a simpler API for the sometimes rather cryptic API that is part of standard java.

Note: If you want so use strong encryption with Oracle's JVM you will need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files for your JDK/JRE.
