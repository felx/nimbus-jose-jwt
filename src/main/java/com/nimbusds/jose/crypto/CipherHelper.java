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
 * @version 2014-01-22
 */
@ThreadSafe
class CipherHelper {


	/**
	 * Instantiates a cipher with an (optional) JCA provider.
	 *
	 * @param name     The name of the cipher. Must not be {@code null}.
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
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
