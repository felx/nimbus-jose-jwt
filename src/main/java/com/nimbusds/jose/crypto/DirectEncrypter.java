package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * Direct encrypter of {@link com.nimbusds.jose.JWEObject JWE objects} with a
 * shared symmetric key. This class is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#DIR}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-11-25)
 */
public class DirectEncrypter extends DirectCryptoProvider implements JWEEncrypter {


	/**
	 * Random byte generator.
	 */
	private static SecureRandom randomGen;


	/**
	 * Initialises the secure random byte generator.
	 *
	 * @throws JOSEException If the secure random byte generator couldn't 
	 *                       be instantiated.
	 */
	private void initSecureRandom()
		throws JOSEException {

		try {
			randomGen = SecureRandom.getInstance("SHA1PRNG");

		} catch(NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a new direct encrypter.
	 *
	 * @param key The shared symmetric key. Its algorithm must be "AES".
	 *            Must be 128 bits (16 bytes), 256 bits (32 bytes) or 512 
	 *            bits (64 bytes) long. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key length or algorithm are unexpected,
	 *                       or if the underlying secure random generator 
	 *                       couldn't be instantiated.
	 */
	public DirectEncrypter(final SecretKey key)
		throws JOSEException {

		super(key);

		if (randomGen == null) {

			initSecureRandom();
		}
	}


	/**
	 * Creates a new direct encrypter.
	 *
	 * @param keyBytes The shared symmetric key, as a byte array. Must be 
	 *                 128 bits (16 bytes), 256 bits (32 bytes) or 512 bits
	 *                 (64 bytes) long. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key length or algorithm are unexpected,
	 *                       or if the underlying secure random generator 
	 *                       couldn't be instantiated.
	 */
	public DirectEncrypter(final byte[] keyBytes)
		throws JOSEException {

		super(keyBytes);

		initSecureRandom();
	}


	@Override
	public JWECryptoParts encrypt(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();

		if (! alg.equals(JWEAlgorithm.DIR)) {

			throw new JOSEException("Unsupported JWE algorithm, must be \"dir\"");
		}

		// Check key length matches matches encryption method
		EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

		if (enc.cekBitLength() != getKey().getEncoded().length * 8) {

			throw new JOSEException("The Content Encryption Key (CEK) length must be " + enc.cekBitLength() + " bits for " + enc + " encryption");
		}

		final Base64URL encryptedKey = null; // The second JWE part


		// Apply compression if instructed
		byte[] plainText = DeflateHelper.applyCompression(readOnlyJWEHeader, bytes);


		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(readOnlyJWEHeader.toBase64URL().toString());
		

		// Encrypt the plain text according to the JWE enc
		byte[] iv;
		AuthenticatedCipherText authCipherText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A192CBC_HS384) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			iv = AESCBC.generateIV(randomGen);

			authCipherText = AESCBC.encryptAuthenticated(getKey(), iv, plainText, aad);

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A192GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			iv = AESGCM.generateIV(randomGen);

			authCipherText = AESGCM.encrypt(getKey(), iv, plainText, aad);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A128GCM");
		}

		return new JWECryptoParts(encryptedKey,  
			                  Base64URL.encode(iv), 
			                  Base64URL.encode(authCipherText.getCipherText()),
			                  Base64URL.encode(authCipherText.getAuthenticationTag()));
	}
}