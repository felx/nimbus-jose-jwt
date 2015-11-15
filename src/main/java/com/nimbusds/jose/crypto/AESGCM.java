package com.nimbusds.jose.crypto;


import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.ByteUtils;


/**
 * AES/GSM/NoPadding encryption and decryption methods. Uses the 
 * BouncyCastle.org provider. This class is thread-safe.
 *
 * <p>See RFC 7518 (JWA), section 5.1 and appendix 3.
 *
 * @author Vladimir Dzhuvinov
 * @author Axel Nennker
 * @version 2015-11-15
 */
@ThreadSafe
class AESGCM {


	/**
	 * The standard Initialisation Vector (IV) length (96 bits).
	 */
	public static final int IV_BIT_LENGTH = 96;


	/**
	 * The standard authentication tag length (128 bits).
	 */
	public static final int AUTH_TAG_BIT_LENGTH = 128;


	/**
	 * Generates a random 96 bit (12 byte) Initialisation Vector(IV) for
	 * use in AES-GCM encryption.
	 *
	 * <p>See RFC 7518 (JWA), section 5.3.
	 *
	 * @param randomGen The secure random generator to use. Must be 
	 *                  correctly initialised and not {@code null}.
	 *
	 * @return The random 96 bit IV, as 12 byte array.
	 */
	public static byte[] generateIV(final SecureRandom randomGen) {
		
		byte[] bytes = new byte[IV_BIT_LENGTH / 8];
		randomGen.nextBytes(bytes);
		return bytes;
	}


	/**
	 * Encrypts the specified plain text using AES/GCM/NoPadding.
	 *
	 * @param secretKey The AES key. Must not be {@code null}.
	 * @param plainText The plain text. Must not be {@code null}.
	 * @param iv        The initialisation vector (IV). Must not be
	 *                  {@code null}.
	 * @param authData  The authenticated data. Must not be {@code null}.
	 *
	 * @return The authenticated cipher text.
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static AuthenticatedCipherText encrypt(final SecretKey secretKey, 
		                                      final byte[] iv,
		                                      final byte[] plainText, 
		                                      final byte[] authData,
		                                      final Provider provider)
		throws JOSEException {

		Cipher cipher;

		try {
			if (provider != null) {
				cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
			} else {
				cipher = Cipher.getInstance("AES/GCM/NoPadding");
			}

			GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_BIT_LENGTH, iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {

			throw new JOSEException("Couldn't create AES/GCM/NoPadding cipher: " + e.getMessage(), e);

		} catch (NoClassDefFoundError e) {
			// We have Java 6, GCMParameterSpec not available,
			// switch to BouncyCastle API
			return LegacyAESGCM.encrypt(secretKey, iv, plainText, authData);
		}

		cipher.updateAAD(authData);

		byte[] cipherOutput;

		try {
			cipherOutput = cipher.doFinal(plainText);

		} catch (IllegalBlockSizeException | BadPaddingException e) {

			throw new JOSEException("Couldn't encrypt with AES/GCM/NoPadding: " + e.getMessage(), e);
		}

		final int tagPos = cipherOutput.length - ByteUtils.byteLength(AUTH_TAG_BIT_LENGTH);

		byte[] cipherText = ByteUtils.subArray(cipherOutput, 0, tagPos);
		byte[] authTag = ByteUtils.subArray(cipherOutput, tagPos, ByteUtils.byteLength(AUTH_TAG_BIT_LENGTH));

		return new AuthenticatedCipherText(cipherText, authTag);
	}


	/**
	 * Decrypts the specified cipher text using AES/GCM/NoPadding.
	 *
	 * @param secretKey  The AES key. Must not be {@code null}.
	 * @param iv         The initialisation vector (IV). Must not be
	 *                   {@code null}.
	 * @param cipherText The cipher text. Must not be {@code null}.
	 * @param authData   The authenticated data. Must not be {@code null}.
	 * @param authTag    The authentication tag. Must not be {@code null}.
	 *
	 * @return The decrypted plain text.
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static byte[] decrypt(final SecretKey secretKey, 
		                     final byte[] iv,
		                     final byte[] cipherText,
		                     final byte[] authData,
		                     final byte[] authTag,
		                     final Provider provider)
		throws JOSEException {

		Cipher cipher;

		try {
			if (provider != null) {
				cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
			} else {
				cipher = Cipher.getInstance("AES/GCM/NoPadding");
			}

			GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_BIT_LENGTH, iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {

			throw new JOSEException("Couldn't create AES/GCM/NoPadding cipher: " + e.getMessage(), e);

		} catch (NoClassDefFoundError e) {
			// We have Java 6, GCMParameterSpec not available,
			// switch to BouncyCastle API
			return LegacyAESGCM.decrypt(secretKey, iv, cipherText, authData, authTag);
		}

		cipher.updateAAD(authData);

		try {
			return cipher.doFinal(ByteUtils.concat(cipherText, authTag));

		} catch (IllegalBlockSizeException | BadPaddingException e) {

			throw new JOSEException("AES/GCM/NoPadding decryption failed: " + e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private AESGCM() { }
}