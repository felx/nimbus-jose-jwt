/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto;


import java.security.*;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.Container;


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
	 * @param secretKey   The AES key. Must not be {@code null}.
	 * @param plainText   The plain text. Must not be {@code null}.
	 * @param ivContainer The initialisation vector (IV). Must not be {@code null}.
	 *                    This is both input and output parameter. On input, it carries externally-generated IV;
	 *                    on output, it carries the IV the cipher actually used. JCA/JCE providers may
	 *                    prefer to use internally-generated IV, e.g. as described
	 *                    <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">by NIST</a>.
	 * @param authData    The authenticated data. Must not be {@code null}.
	 *
	 * @return The authenticated cipher text.
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static AuthenticatedCipherText encrypt(final SecretKey secretKey, 
		                                      final Container<byte[]> ivContainer,
		                                      final byte[] plainText, 
		                                      final byte[] authData,
		                                      final Provider provider)
		throws JOSEException {

		Cipher cipher;

		byte[] iv = ivContainer.get();

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

		// retrieve the actual IV used by the cipher -- it may be internally-generated.
		ivContainer.set(actualIvOf(cipher));

		return new AuthenticatedCipherText(cipherText, authTag);
	}

	/**
	 * Assembles together the retrieval of the actual algorithm parameters, and their validation.
	 *
	 * @param cipher to interrogate for the parameters it actually used.
	 *
	 * @return the IV used by the specified cipher.
	 *
	 * @throws JOSEException if unable to ascertain the actual IV is usable.
	 *
	 * @see {@link #actualParamsOf(Cipher)}
	 * @see #validate(byte[], int)
	 */
	private static byte[] actualIvOf(Cipher cipher) throws JOSEException {
		GCMParameterSpec actualParams = actualParamsOf(cipher);

		byte[] iv = actualParams.getIV();
		int tLen = actualParams.getTLen();

		validate(iv, tLen);

		return iv;
	}

	/**
	 * Enforces JWA requirements on AES GCM algorithm parameters.
	 * See e.g. <a href="https://tools.ietf.org/html/rfc7518#section-5.3">JWA RFC</a>.
	 *
	 * @param iv to check for compliance.
	 * @param tLen to check for compliance.
	 *
	 * @throws JOSEException if the parameters do not match standard requirements.
	 *
	 * @see #IV_BIT_LENGTH
	 * @see #AUTH_TAG_BIT_LENGTH
	 */
	private static void validate(byte[] iv, int tLen) throws JOSEException {
		if (ByteUtils.bitLength(iv) != IV_BIT_LENGTH) {
			throw new JOSEException(String.format("IV length of %d bits is required, got %d", IV_BIT_LENGTH, ByteUtils.bitLength(iv)));
		}

		if (tLen != AUTH_TAG_BIT_LENGTH) {
			throw new JOSEException(String.format("Authentication tag length of %d bits is required, got %d.", AUTH_TAG_BIT_LENGTH, tLen));
		}
	}

	/**
	 * Retrieves the actual AES GCM parameters used by the specified cipher.
	 *
	 * @param cipher to interrogate; non-{@code null}.
	 *
	 * @return non-{@code null}.
	 *
	 * @throws JOSEException if the parameters cannot be retrieved, or are uninitialized or not in the correct form.
	 * We want to have the actual parameters used by the cipher and not rely on the assumption that they were the same as those we supplied it with.
	 * If at runtime the assumption was incorrect, the ciphertext would not be decryptable.
	 */
	private static GCMParameterSpec actualParamsOf(Cipher cipher) throws JOSEException {
		AlgorithmParameters algorithmParameters = cipher.getParameters();
		if (algorithmParameters == null) {
			throw new JOSEException("AES GCM ciphers are expected to make use of algorithm parameters");
		}

		try {
			return algorithmParameters.getParameterSpec(GCMParameterSpec.class);
		} catch (InvalidParameterSpecException shouldNotHappen) {
			throw new JOSEException(shouldNotHappen.getMessage(), shouldNotHappen);
		}
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