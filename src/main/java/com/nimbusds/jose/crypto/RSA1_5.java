package com.nimbusds.jose.crypto;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;


/**
 * RSAES-PKCS1-V1_5 methods for Content Encryption Key (CEK) encryption and
 * decryption.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-06)
 */
class RSA1_5 {


	/**
	 * Encrypts the specified Content Encryption Key (CEK).
	 *
	 * @param pub The public RSA key. Must not be {@code null}.
	 * @param cek The Content Encryption Key (CEK) to encrypt. Must not be
	 *            {@code null}.
	 *
	 * @return The encrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek)
		throws JOSEException {

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pub);
			return cipher.doFinal(cek.getEncoded());

		} catch (Exception e) {

			// java.security.NoSuchAlgorithmException
			// java.security.InvalidKeyException
			// javax.crypto.IllegalBlockSizeException
			throw new JOSEException("Couldn't encrypt Content Encryption Key (CEK): " + e.getMessage(), e);
		}
	}


	/**
	 * Decrypts the specified encrypted Content Encryption Key (CEK).
	 *
	 * @param priv         The private RSA key. Must not be {@code null}.
	 * @param encryptedCEK The encrypted Content Encryption Key (CEK) to
	 *                     decrypt. Must not be {@code null}.
	 *
	 * @return The decrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static SecretKey decryptCEK(final RSAPrivateKey priv, 
		                           final byte[] encryptedCEK,
		                           final int keyLength)
		throws JOSEException {

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, priv);
			byte[] secretKeyBytes = cipher.doFinal(encryptedCEK);

			if (8 * secretKeyBytes.length != keyLength) {

				throw new JOSEException("CEK key length mismatch: " + 
					                secretKeyBytes.length + " != " + keyLength);
			}

			return new SecretKeySpec(secretKeyBytes, "AES");

		} catch (Exception e) {

			// java.security.NoSuchAlgorithmException
			// java.security.InvalidKeyException
			// javax.crypto.IllegalBlockSizeException
			throw new JOSEException("Couldn't decrypt Content Encryption Key (CEK): " + e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private RSA1_5() { }
}