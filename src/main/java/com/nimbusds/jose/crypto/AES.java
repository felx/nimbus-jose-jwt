package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import com.nimbusds.jose.JOSEException;


/**
 * AES encryption, decryption and key generation methods. Uses the 
 * BouncyCastle.org provider. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-05)
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
	 * Creates a new AES cipher.
	 *
	 * @param secretKey     The AES key. Must not be {@code null}.
	 * @param forEncryption If {@code true} creates an AES encryption
	 *                      cipher, else creates an AES decryption 
	 *                      cipher.
	 *
	 * @return The AES cipher.
	 */
	public static AESEngine createCipher(final SecretKey secretKey, 
		                             final boolean forEncryption) {

		AESEngine cipher = new AESEngine();

		CipherParameters cipherParams = new KeyParameter(secretKey.getEncoded());

		cipher.init(forEncryption, cipherParams);

		return cipher;
	}


	/**
	 * Prevents public instantiation.
	 */
	private AES() { }
}