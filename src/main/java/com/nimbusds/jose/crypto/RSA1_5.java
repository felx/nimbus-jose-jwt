package com.nimbusds.jose.crypto;


import java.security.Provider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;


/**
 * RSAES-PKCS1-V1_5 methods for Content Encryption Key (CEK) encryption and
 * decryption. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-01-24
 */
@ThreadSafe
class RSA1_5 {


	/**
	 * Encrypts the specified Content Encryption Key (CEK).
	 *
	 * @param pub      The public RSA key. Must not be {@code null}.
	 * @param cek      The Content Encryption Key (CEK) to encrypt. Must
	 *                 not be {@code null}.
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 *
	 * @return The encrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek, Provider provider)
		throws JOSEException {

		try {
			Cipher cipher = CipherHelper.getInstance("RSA/ECB/PKCS1Padding", provider);
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
	 * @param provider     The JCA provider, or {@code null} to use the
	 *                     default one.
	 *
	 * @return The decrypted Content Encryption Key (CEK), {@code null} if
	 *         there was a CEK key length mismatch.
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static SecretKey decryptCEK(final RSAPrivateKey priv, 
		                           final byte[] encryptedCEK,
		                           final int keyLength,
		                           final Provider provider)
		throws JOSEException {

		try {
			Cipher cipher = CipherHelper.getInstance("RSA/ECB/PKCS1Padding", provider);
			cipher.init(Cipher.DECRYPT_MODE, priv);
			byte[] secretKeyBytes = cipher.doFinal(encryptedCEK);

			if (8 * secretKeyBytes.length != keyLength) {
				// CEK key length mismatch
				return null;
			}

			return new SecretKeySpec(secretKeyBytes, "AES");

		} catch (Exception e) {

			// java.security.NoSuchAlgorithmException
			// java.security.InvalidKeyException
			// javax.crypto.IllegalBlockSizeException
			// javax.crypto.BadPaddingException
			throw new JOSEException("Couldn't decrypt Content Encryption Key (CEK): " + e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private RSA1_5() { }
}