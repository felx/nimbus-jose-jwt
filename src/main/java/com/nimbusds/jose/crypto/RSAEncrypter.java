package com.nimbusds.jose.crypto;


import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
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
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;


	/**
	 * Creates a new RSA encrypter.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 */
	public RSAEncrypter(final RSAPublicKey publicKey) {

		if (publicKey == null) {
			throw new IllegalArgumentException("The public RSA key must not be null");
		}

		this.publicKey = publicKey;
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
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] bytes)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final EncryptionMethod enc = header.getEncryptionMethod();

		// Generate and encrypt the CEK according to the enc method
		final SecureRandom randomGen = getSecureRandom();
		final SecretKey cek = AES.generateKey(enc.cekBitLength(), randomGen);

		Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			encryptedKey = Base64URL.encode(RSA1_5.encryptCEK(publicKey, cek, keyEncryptionProvider));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			encryptedKey = Base64URL.encode(RSA_OAEP.encryptCEK(publicKey, cek, keyEncryptionProvider));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
			
			encryptedKey = Base64URL.encode(RSA_OAEP_256.encryptCEK(publicKey, cek, keyEncryptionProvider));
			
		} else {

			throw new JOSEException("Unsupported JWE algorithm, must be RSA1_5, RSA-OAEP, or RSA-OAEP-256");
		}


		// Apply compression if instructed
		byte[] plainText = DeflateHelper.applyCompression(header, bytes);

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(header.toBase64URL().toString());

		// Encrypt the plain text according to the JWE enc
		byte[] iv;
		AuthenticatedCipherText authCipherText;
		
		if (enc.equals(EncryptionMethod.A128CBC_HS256) ||
		    enc.equals(EncryptionMethod.A192CBC_HS384) ||
		    enc.equals(EncryptionMethod.A256CBC_HS512)    ) {

			iv = AESCBC.generateIV(randomGen);

			authCipherText = AESCBC.encryptAuthenticated(
				cek, iv, plainText, aad,
				contentEncryptionProvider, macProvider);

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			   enc.equals(EncryptionMethod.A192GCM) ||
			   enc.equals(EncryptionMethod.A256GCM)    ) {

			iv = AESGCM.generateIV(randomGen);

			authCipherText = AESGCM.encrypt(
				cek, iv, plainText, aad,
				contentEncryptionProvider);

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			   enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)    ) {

			iv = AESCBC.generateIV(randomGen);

			authCipherText = AESCBC.encryptWithConcatKDF(
				header, cek, encryptedKey, iv, plainText,
				contentEncryptionProvider, macProvider);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}

		return new JWECryptoParts(encryptedKey,  
			                  Base64URL.encode(iv), 
			                  Base64URL.encode(authCipherText.getCipherText()),
			                  Base64URL.encode(authCipherText.getAuthenticationTag()));
	}
}