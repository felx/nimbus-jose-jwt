package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;


/**
 * AES key generation utility. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-07)
 */
@ThreadSafe
class AES {


	/**
	 * Returns a new AES key generator instance.
	 *
	 * @param provider The specific JCA provider, {@code null} to use the
	 *                 default system one.
	 *
	 * @return The AES key generator.
	 *
	 * @throws JOSEException If an AES key generator couldn't be
	 *                       instantiated.
	 */
	public static KeyGenerator createKeyGenerator(final Provider provider)
		throws JOSEException {

		try {
			if (provider != null) {
				return KeyGenerator.getInstance("AES", provider);
			} else {
				return KeyGenerator.getInstance("AES");
			}

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Generates an AES key of the specified length.
	 *
	 * @param keyBitLength The key length, in bits.
	 * @param provider     The specific JCA provider, {@code null} to use
	 *                     the default system one.
	 * @param random       The secure random generator. Must not be
	 *                     {@code null}.
	 *
	 * @return The AES key.
	 *
	 * @throws JOSEException If an AES key couldn't be generated.
	 */
	public static SecretKey generateKey(final int keyBitLength,
					    final Provider provider,
					    final SecureRandom random)
		throws JOSEException {

		KeyGenerator aesKeyGenerator = createKeyGenerator(provider);
		aesKeyGenerator.init(keyBitLength, random);
		return aesKeyGenerator.generateKey();
	}


	/**
	 * Prevents public instantiation.
	 */
	private AES() { }
}