package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;



/**
 * Message Authentication Code (MAC) signer of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-20)
 */
@ThreadSafe
public class MACSigner extends MACProvider implements JWSSigner {


	/**
	 * Returns the minimal required secret length for the specified HMAC
	 * JWS algorithm.
	 *
	 * @param hmacAlg The HMAC JWS algorithm. Must be
	 *                {@link #SUPPORTED_ALGORITHMS supported} and not
	 *                {@code null}.
	 *
	 * @return The minimal required secret length, in bits.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static int getMinRequiredSecretLength(final JWSAlgorithm hmacAlg)
		throws JOSEException {

		if (JWSAlgorithm.HS256.equals(hmacAlg)) {
			return 256;
		} else if (JWSAlgorithm.HS384.equals(hmacAlg)) {
			return 384;
		} else if (JWSAlgorithm.HS512.equals(hmacAlg)) {
			return 512;
		} else {
			throw new JOSEException("Unsupported HMAC algorithm, must be HS256, HS384 or HS512");
		}
	}


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param secret The secret. Must be at least 256 bits long and not
	 *               {@code null}.
	 */
	public MACSigner(final byte[] secret) {

		super(secret);
	}


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param secretString The secret as a UTF-8 encoded string. Must be at
	 *                     least 256 bits long and not {@code null}.
	 */
	public MACSigner(final String secretString) {

		this(secretString.getBytes(Charset.forName("UTF-8")));
	}


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param secretKey The secret key. Must be at least 256 bits long and
	 *                  not {@code null}.
	 */
	public MACSigner(final SecretKey secretKey) {

		this(secretKey.getEncoded());
	}


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param jwk The secret as a JWK. Must be at least 256 bits long and
	 *            not {@code null}.
	 */
	public MACSigner(final OctetSequenceKey jwk) {

		this(jwk.toByteArray());
	}


	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException {

		final int minRequiredLength = getMinRequiredSecretLength(header.getAlgorithm());

		if (getSecret().length < minRequiredLength / 8) {
			throw new JOSEException("The secret must be at least " + minRequiredLength + " bits long for " + header.getAlgorithm());
		}

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
		byte[] hmac = HMAC.compute(jcaAlg, getSecret(), signingInput, getJCAProvider());
		return Base64URL.encode(hmac);
	}
}
