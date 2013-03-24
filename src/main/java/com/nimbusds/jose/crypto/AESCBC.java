package com.nimbusds.jose.crypto;


import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEException;


/**
 * Constants and static methods for AES/CBC/PKCS5Padding encryption and 
 * decryption.
 *
 * <p>See draft-ietf-jose-json-web-algorithms-08, section 4.8.
 *
 * @author Vladimir Dzhuvinov
 * @author Axel Nennker
 * @version $version$ (2013-03-23)
 */
class AESCBC {


	/**
	 * The standard Initialisation Vector (IV) length (128 bits).
	 */
	public static final int IV_BIT_LENGTH = 128;


	/**
	 * Generates a random 128 bit (16 byte) Initialisation Vector(IV) for
	 * use in AES-CBC encryption.
	 *
	 * @param randomGen The secure random generator to use. Must be 
	 *                  correctly initialised and not {@code null}.
	 *
	 * @return The random 128 bit IV.
	 */
	public static byte[] generateIV(final SecureRandom randomGen) {
		
		byte[] bytes = new byte[IV_BIT_LENGTH];

		randomGen.nextBytes(bytes);

		return bytes;
	}


	/**
	 * Creates a new AES/CBC/PKCS5Padding cipher.
	 *
	 * @param secretKey     The AES key. Must not be {@code null}.
	 * @param forEncryption If {@code true} creates an encryption cipher, 
	 *                      else creates a decryption cipher.
	 * @param iv            The initialisation vector (IV). Must not be
	 *                      {@code null}.
	 *
	 * @return The AES/CBC/PKCS5Padding cipher.
	 */
	private static Cipher createAESCBCCipher(final SecretKey secretKey,
		                                 final boolean forEncryption,
		                                 final byte[] iv)
		throws JOSEException {

		Cipher cipher;

		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			SecretKeySpec keyspec = new SecretKeySpec(secretKey.getEncoded(), "AES");

			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			if (forEncryption) {

				cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivSpec);

			} else {

				cipher.init(Cipher.DECRYPT_MODE, keyspec, ivSpec);
			}

		} catch (Exception e) {

			throw new JOSEException(e.getMessage(), e);
		}

		return cipher;
	}


	/**
	 * Encrypts the specified plain text using AES/CBC/PKCS5Padding.
	 *
	 * @param secretKey The AES key. Must not be {@code null}.
	 * @param iv        The initialisation vector (IV). Must not be
	 *                  {@code null}.
	 * @param plainText The plain text. Must not be {@code null}.
	 *
	 * @return The cipher text.
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encrypt(final SecretKey secretKey, 
		                     final byte[] iv,
		                     final byte[] plainText)
		throws JOSEException {

		Cipher cipher = createAESCBCCipher(secretKey, true, iv);

		try {
			return cipher.doFinal(plainText);	
		
		} catch (Exception e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Decrypts the specified cipher text using AES/CBC/PKCS5Padding.
	 *
	 * @param secretKey  The AES key. Must not be {@code null}.
	 * @param iv         The initialisation vector (IV). Must not be
	 *                   {@code null}.
	 * @param cipherText The cipher text. Must not be {@code null}.
	 *
	 * @return The decrypted plain text.
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static byte[] decrypt(final SecretKey secretKey, 
		                     final byte[] iv,
		                     final byte[] cipherText)
		throws JOSEException {

		Cipher cipher = createAESCBCCipher(secretKey, false, iv);

		try {
			return cipher.doFinal(cipherText);

		} catch (Exception e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private AESCBC() { }
}