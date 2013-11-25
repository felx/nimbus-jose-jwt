package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

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
 * RSA encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP}
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
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-11-25)
 */
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


	/**
	 * Random byte generator.
	 */
	private static SecureRandom randomGen;


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;


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
	 * Creates a new RSA encrypter.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the underlying secure random generator
	 *                       couldn't be instantiated.
	 */
	public RSAEncrypter(final RSAPublicKey publicKey)
		throws JOSEException {

		if (publicKey == null) {

			throw new IllegalArgumentException("The public RSA key must not be null");
		}

		this.publicKey = publicKey;


		if (randomGen == null) {

			initSecureRandom();
		}
	}


	/**
	 * Gets the public RSA key.
	 *
	 * @return The public RSA key.
	 */
	public RSAPublicKey getPublicKey() {

		return publicKey;
	}


	@Override
	public JWECryptoParts encrypt(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();
		EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

		// Generate and encrypt the CEK according to the enc method
		SecretKey cek = AES.generateKey(enc.cekBitLength());

		Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			encryptedKey = Base64URL.encode(RSA1_5.encryptCEK(publicKey, cek));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			encryptedKey = Base64URL.encode(RSA_OAEP.encryptCEK(publicKey, cek));

		} else {

			throw new JOSEException("Unsupported JWE algorithm, must be RSA1_5 or RSA-OAEP");
		}


		// Apply compression if instructed
		byte[] plainText = DeflateHelper.applyCompression(readOnlyJWEHeader, bytes);

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(readOnlyJWEHeader.toBase64URL().toString());

		// Encrypt the plain text according to the JWE enc
		byte[] iv;
		AuthenticatedCipherText authCipherText;
		
		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A192CBC_HS384) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			iv = AESCBC.generateIV(randomGen);

			authCipherText = AESCBC.encryptAuthenticated(cek, iv, plainText, aad);

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A192GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			iv = AESGCM.generateIV(randomGen);

			authCipherText = AESGCM.encrypt(cek, iv, plainText, aad);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}

		return new JWECryptoParts(encryptedKey,  
			                  Base64URL.encode(iv), 
			                  Base64URL.encode(authCipherText.getCipherText()),
			                  Base64URL.encode(authCipherText.getAuthenticationTag()));
	}
}