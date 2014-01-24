package com.nimbusds.jose.crypto;


import net.jcip.annotations.ThreadSafe;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;


/**
 * Helper utilities for instantiating ciphers.
 *
 * @author Cedric Staub
 * @version $version$ (2014-01-22)
 */
@ThreadSafe
class CipherHelper {


	/**
	 * Instantiates a cipher with an (optional) provider.
	 *
	 * @param name      The name of the cipher.
	 * @param provider  The cryptographic provider to use (or {@code null}).
	 */
	public static Cipher getInstance(String name, Provider provider)
		throws NoSuchAlgorithmException, NoSuchPaddingException {

		if (provider == null) {
			return Cipher.getInstance(name);
		} else {
			return Cipher.getInstance(name, provider);
		}
	}
}
