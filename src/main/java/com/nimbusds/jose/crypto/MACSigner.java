package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;



/**
 * Message Authentication Code (MAC) signer of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
@ThreadSafe
public class MACSigner extends MACProvider implements JWSSigner {


	/**
	 * Returns the minimal required secret length for the specified HMAC
	 * JWS algorithm.
	 *
	 * @param alg The HMAC JWS algorithm. Must be
	 *            {@link #SUPPORTED_ALGORITHMS supported} and not
	 *            {@code null}.
	 *
	 * @return The minimal required secret length, in bits.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static int getMinRequiredSecretLength(final JWSAlgorithm alg)
		throws JOSEException {

		if (JWSAlgorithm.HS256.equals(alg)) {
			return 256;
		} else if (JWSAlgorithm.HS384.equals(alg)) {
			return 384;
		} else if (JWSAlgorithm.HS512.equals(alg)) {
			return 512;
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg,
				SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * Returns the supported JWS HMAC algorithms for the specified secret
	 * length.
	 *
	 * @param secretLength The secret length in bits. Must not be negative.
	 *
	 * @return The supported JWS HMAC algorithms, empty set if the secret
	 *         length is too short for any algorithm.
	 */
	public static Set<JWSAlgorithm> getHMACAlgorithms(final int secretLength) {

		Set<JWSAlgorithm> hmacAlgs = new LinkedHashSet<>();

		if (secretLength >= 256)
			hmacAlgs.add(JWSAlgorithm.HS256);

		if (secretLength >= 384)
			hmacAlgs.add(JWSAlgorithm.HS384);

		if (secretLength >= 512)
			hmacAlgs.add(JWSAlgorithm.HS512);

		return Collections.unmodifiableSet(hmacAlgs);
	}


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param secret The secret. Must be at least 256 bits long and not
	 *               {@code null}.
	 */
	public MACSigner(final byte[] secret) {

		super(secret, getHMACAlgorithms(ByteUtils.bitLength(secret.length)));
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

		if (getSecret().length < ByteUtils.byteLength(minRequiredLength)) {
			throw new JOSEException("The secret length for " + header.getAlgorithm() + " must be at least " + minRequiredLength + " bits");
		}

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
		byte[] hmac = HMAC.compute(jcaAlg, getSecret(), signingInput, getJCAProvider());
		return Base64URL.encode(hmac);
	}
}
