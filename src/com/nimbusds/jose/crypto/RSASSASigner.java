package com.nimbusds.jose.crypto;


import java.security.Signature;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import java.security.interfaces.RSAPrivateKey;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSSigner;
import com.nimbusds.jose.sdk.ReadOnlyJWSHeader;

import com.nimbusds.jose.sdk.util.Base64URL;



/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) signer of 
 * {@link com.nimbusds.jose.sdk.JWSObject JWS objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#RS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
 */
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

		if (privateKey == null)
			throw new IllegalArgumentException("The private RSA key must not be null");
		
		this.privateKey = privateKey;
	}


	@Override
	public Base64URL sign(final ReadOnlyJWSHeader header, final byte[] signableContent)
		throws JOSEException {
		
		ensureAcceptedAlgorithm(header.getAlgorithm());
		
		Signature signer = getRSASignerAndVerifier(header.getAlgorithm());
		
		try {
			signer.initSign(privateKey);
			signer.update(signableContent);
			return Base64URL.encode(signer.sign());
			
		} catch (InvalidKeyException e) {
		
			throw new JOSEException("Invalid private RSA key: " + e.getMessage(), e);
			
		} catch (SignatureException e) {
		
			throw new JOSEException("RSA signature exception: " + e.getMessage(), e);
		}
	}
}
