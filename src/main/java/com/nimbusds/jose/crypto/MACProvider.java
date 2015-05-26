package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
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
abstract class MACProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the MAC provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWSAlgorithm.HS256);
		algs.add(JWSAlgorithm.HS384);
		algs.add(JWSAlgorithm.HS512);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Gets the matching Java Cryptography Architecture (JCA) algorithm 
	 * name for the specified HMAC-based JSON Web Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return The matching JCA algorithm name.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static String getJCAAlgorithmName(final JWSAlgorithm alg)
		throws JOSEException {

		if (alg.equals(JWSAlgorithm.HS256)) {
			return "HMACSHA256";
		} else if (alg.equals(JWSAlgorithm.HS384)) {
			return "HMACSHA384";
		} else if (alg.equals(JWSAlgorithm.HS512)) {
			return "HMACSHA512";
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg,
				SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * The secret.
	 */
	private final byte[] secret;


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param secret        The secret. Must be at least 256 bits long and
	 *                      not {@code null}.
	 * @param supportedAlgs The supported HMAC algorithms. Must not be
	 *                      {@code null}.
	 *
	 * @throws JOSEException If the secret length is shorter than the
	 *                       minimum 256-bit requirement.
	 */
	protected MACProvider(final byte[] secret,
			      final Set<JWSAlgorithm> supportedAlgs)
		throws JOSEException {

		super(supportedAlgs);

		if (secret.length < 256 / 8) {
			throw new JOSEException("The secret length must be at least 256 bits");
		}

		this.secret = secret;
	}


	/**
	 * Gets the secret key.
	 *
	 * @return The secret key.
	 */
	public SecretKey getSecretKey() {

		return new SecretKeySpec(secret, "MAC");
	}


	/**
	 * Gets the secret bytes.
	 *
	 * @return The secret bytes.
	 */
	public byte[] getSecret() {

		return secret;
	}


	/**
	 * Gets the secret as a UTF-8 encoded string.
	 *
	 * @return The secret as a UTF-8 encoded string.
	 */
	public String getSecretString() {

		return new String(secret, Charset.forName("UTF-8"));
	}
}
