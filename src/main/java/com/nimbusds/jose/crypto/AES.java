package com.nimbusds.jose.crypto;


import javax.crypto.SecretKey;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import com.nimbusds.jose.JOSEException;


/**
 * Constants and static methods for AES encryption and decryption. Uses the 
 * BouncyCastle.org provider.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
class AES {


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
	public static AESEngine createAESCipher(final SecretKey secretKey, 
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