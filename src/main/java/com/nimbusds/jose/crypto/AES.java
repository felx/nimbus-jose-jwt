package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import com.nimbusds.jose.JOSEException;


/**
 * AES encryption, decryption and key generation methods. Uses the 
 * BouncyCastle.org provider.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-10-16)
 */
class AES {


	/**
	 * Generates an AES key of the specified length.
	 *
	 * @param keyBitLength The key length, in bits.
	 *
	 * @return The AES key.
	 *
	 * @throws JOSEException If an AES key couldn't be generated.
	 */
	public static SecretKey generateKey(final int keyBitLength) 
		throws JOSEException {

		KeyGenerator keygen;

		try {
			keygen = KeyGenerator.getInstance("AES", BouncyCastleProviderSingleton.getInstance());

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		keygen.init(keyBitLength);
		return keygen.generateKey();
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