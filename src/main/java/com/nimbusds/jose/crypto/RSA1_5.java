package com.nimbusds.jose.crypto;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;


/**
 * Static methods for RSAES-PKCS1-V1_5 Content Master Key (CMK) encryption and
 * decryption. Uses the BouncyCastle.org provider.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
class RSA1_5 {


	/**
	 * Encrypts the specified Content Master Key (CMK).
	 *
	 * @param publicKey        The public RSA key. Must not be 
	 *                         {@code null}.
	 * @param contentMasterKey The Content Master Key (CMK). Must not be
	 *                         {@code null}.
	 *
	 * @return The encrypted Content Master Key (CMK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encryptCMK(final RSAPublicKey publicKey,
		                        final SecretKey contentMasterKey)
		throws JOSEException {

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(contentMasterKey.getEncoded());

		} catch (Exception e) {

			// java.security.NoSuchAlgorithmException
			// java.security.InvalidKeyException
			// javax.crypto.IllegalBlockSizeException
			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Decrypts the Content Master Key (CMK).
	 *
	 * @param privateKey   The private RSA key. Must not be {@code null}.
	 * @param encryptedCMK The encrypted Content Master Key (CMK). Must not
	 *                     be {@code null}.
	 *
	 * @return The decrypted Content Master Key (CMK).
	 *
	 * @throws JOSEException If derivation failed.
	 */
	public static SecretKeySpec decryptCMK(final RSAPrivateKey privateKey, 
		                               final byte[] encryptedCMK,
		                               final int keyLength)
		throws JOSEException {

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] secretKeyBytes = cipher.doFinal(encryptedCMK);

			if (8 * secretKeyBytes.length != keyLength) {

				throw new JOSEException("CMK key length mismatch: " + 
					                secretKeyBytes.length + " != " + keyLength);
			}

			return new SecretKeySpec(secretKeyBytes, "AES");

		} catch (Exception e) {

			// java.security.NoSuchAlgorithmException
			// java.security.InvalidKeyException
			// javax.crypto.IllegalBlockSizeException
			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private RSA1_5() { }
}