package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;



/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) signer of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS512}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-31)
 */
@ThreadSafe
public class RSASSASigner extends RSASSAProvider implements JWSSigner {


	/**
	 * The private RSA key.
	 */
	private final RSAPrivateKey privateKey;


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
	 *
	 * @param privateKey The private RSA key. Must not be {@code null}.
	 */
	public RSASSASigner(final RSAPrivateKey privateKey) {

		if (privateKey == null) {
			throw new IllegalArgumentException("The private RSA key must not be null");
		}

		this.privateKey = privateKey;
	}


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
	 *
	 * @param rsaJWK The RSA JSON Web Key (JWK). Must contain a private
	 *               part. Must not be {@code null}.
	 *
	 * @throws JOSEException If the RSA JWK doesn't contain a private part
	 *                       or its extraction failed.
	 */
	public RSASSASigner(final RSAKey rsaJWK)
		throws JOSEException {

		if (! rsaJWK.isPrivate()) {
			throw new JOSEException("The RSA JWK doesn't contain a private part");
		}

		privateKey = rsaJWK.toRSAPrivateKey();
	}


	/**
	 * Gets the private RSA key.
	 *
	 * @return The private RSA key.
	 */
	public RSAPrivateKey getPrivateKey() {

		return privateKey;
	}


	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException {

		Signature signer = RSASSA.getSignerAndVerifier(header.getAlgorithm(), getJCAProvider());

		try {
			signer.initSign(privateKey);
			signer.update(signingInput);
			return Base64URL.encode(signer.sign());

		} catch (InvalidKeyException e) {
			throw new JOSEException("Invalid private RSA key: " + e.getMessage(), e);

		} catch (SignatureException e) {
			throw new JOSEException("RSA signature exception: " + e.getMessage(), e);
		}
	}
}
