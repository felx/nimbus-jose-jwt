package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.base64.Base64URL;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signer of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES512}
 * </ul>
 * 
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 2015-06-07
 */
@ThreadSafe
public class ECDSASigner extends ECDSAProvider implements JWSSigner {


	/**
	 * The private EC key.
	 */
	private final ECPrivateKey privateKey;


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * signer.
	 *
	 * @param privateKey The private EC key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSASigner(final ECPrivateKey privateKey)
		throws JOSEException {

		super(ECDSA.resolveAlgorithm(privateKey));

		this.privateKey = privateKey;
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must contain a private part.
	 *              Must not be {@code null}.
	 *
	 * @throws JOSEException If the EC JWK doesn't contain a private part,
	 *                       its extraction failed, or the elliptic curve
	 *                       is not supported.
	 */
	public ECDSASigner(final ECKey ecJWK)
		throws JOSEException {

		super(ECDSA.resolveAlgorithm(ecJWK.getCurve()));

		if (! ecJWK.isPrivate()) {
			throw new JOSEException("The EC JWK doesn't contain a private part");
		}

		privateKey = ecJWK.toECPrivateKey();
	}


	/**
	 * Returns the private EC key.
	 *
	 * @return The private EC key.
	 */
	public ECPrivateKey getPrivateKey() {

		return privateKey;
	}


	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException {

		final JWSAlgorithm alg = header.getAlgorithm();

		if (! supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}

		// DER-encoded signature, according to JCA spec
		// (sequence of two integers - R + S)
		final byte[] jcaSignature;

		try {
			Signature dsa = ECDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
			dsa.initSign(privateKey, getJCAContext().getSecureRandom());
			dsa.update(signingInput);
			jcaSignature = dsa.sign();

		} catch (InvalidKeyException | SignatureException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		final int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
		final byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(jcaSignature, rsByteArrayLength);
		return Base64URL.encode(jwsSignature);
	}
}
