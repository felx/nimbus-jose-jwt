package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
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
 * @version $version$ (2013-05-16)
 */
abstract class MACProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms.
	 */
	private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * Initialises the supported algorithms.
	 */
	static {

		Set<JWSAlgorithm> algs = new HashSet<JWSAlgorithm>();
		algs.add(JWSAlgorithm.HS256);
		algs.add(JWSAlgorithm.HS384);
		algs.add(JWSAlgorithm.HS512);

		SUPPORTED_ALGORITHMS = algs;
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
			
			throw new JOSEException("Unsupported HMAC algorithm, must be HS256, HS384 or HS512");
		}
	}


	/**
	 * The shared secret.
	 */
	private final byte[] sharedSecret;


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param sharedSecret The shared secret. Must not be {@code null}.
	 */
	protected MACProvider(final byte[] sharedSecret) {

		super(SUPPORTED_ALGORITHMS);

		if (sharedSecret == null) {

			throw new IllegalArgumentException("The shared secret must not be null");
		}

		this.sharedSecret = sharedSecret;
	}


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param sharedSecretString The shared secret as a UTF-8 encoded 
	 *                           string. Must not be {@code null}.
	 */
	protected MACProvider(final String sharedSecretString) {

		this(sharedSecretString.getBytes(Charset.forName("UTF-8")));
	}


	/**
	 * Gets the shared secret.
	 *
	 * @return The shared secret.
	 */
	public byte[] getSharedSecret() {

		return sharedSecret;
	}


	/**
	 * Gets the shared secret as a UTF-8 encoded string.
	 *
	 * @return The shared secret as a UTF-8 encoded string.
	 */
	public String getSharedSecretString() {

		return new String(sharedSecret, Charset.forName("UTF-8"));
	}
}
