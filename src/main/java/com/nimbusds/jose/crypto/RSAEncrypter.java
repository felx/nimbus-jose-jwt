package com.nimbusds.jose.crypto;


import java.security.interfaces.RSAPublicKey;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * RSA encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
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
 * @version $version$ (2015-06-08)
 */
@ThreadSafe
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
	 * Creates a new RSA encrypter.
	 *
	 *  @param rsaJWK The RSA JSON Web Key (JWK). Must not be {@code null}.
	 *
	 * @throws JOSEException If the RSA JWK extraction failed.
	 */
	public RSAEncrypter(final RSAKey rsaJWK)
		throws JOSEException {

		this(rsaJWK.toRSAPublicKey());
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
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final EncryptionMethod enc = header.getEncryptionMethod();

		// Generate and encrypt the CEK according to the enc method
		final SecretKey cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());

		final Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			encryptedKey = Base64URL.encode(RSA1_5.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			encryptedKey = Base64URL.encode(RSA_OAEP.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
			
			encryptedKey = Base64URL.encode(RSA_OAEP_256.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));
			
		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}

		return ContentCryptoProvider.encrypt(header, clearText, cek, encryptedKey, getJCAContext());
	}
}