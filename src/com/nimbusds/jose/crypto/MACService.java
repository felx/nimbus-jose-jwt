package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSAlgorithm;


/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.sdk.JWSObject JWS objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#HS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-25)
 */
public abstract class MACService {
	
	
	/**
	 * The supported algorithms.
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
	 * The shared secret.
	 */
	private final byte[] sharedSecret;
	
	
	/**
	 * The accepted algorithms.
	 */
	private final Set<JWSAlgorithm> acceptedAlgorithms;
	
	
	/**
	 * Gets the names of the HMAC algorithms supported by the MAC service.
	 *
	 * @return The supported algorithms.
	 */
	public static Set<JWSAlgorithm> getSupportedAlgorithms() {
	
		return SUPPORTED_ALGORITHMS;
	}
	
	
	/**
	 * Creates a new Message Authentication (MAC) service.
	 *
	 * @param sharedSecret The shared secret. Must not be {@code null}.
	 */
	protected MACService(final byte[] sharedSecret) {

		this(sharedSecret, null);
	}
	
	
	/**
	 * Creates a new Message Authentication (MAC) service.
	 *
	 * @param sharedSecret The shared secret. Must not be {@code null}.
	 * @param acceptedAlgs Specifies the accepted algorithms.
	 */
	protected MACService(final byte[] sharedSecret, final Set<JWSAlgorithm> acceptedAlgs) {
	
		if (sharedSecret == null)
			throw new IllegalArgumentException("The shared secret must not be null");

		this.sharedSecret = sharedSecret;
		
		acceptedAlgorithms = acceptedAlgs;
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
	 * 
	 *
	 */
	public Set<JWSAlgorithm> getAcceptedAlgorithms() {
	
		return acceptedAlgorithms;
	}
	
	
	/**
	 * Gets a Message Authentication Code (MAC) service for the specified
	 * HMAC-based JSON Web Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return A MAC service instance.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static Mac getMAC(final JWSAlgorithm alg)
		throws JOSEException {
		
		// The internal crypto provider uses different alg names
		
		String internalAlgName = null;
		
		if (alg.equals(JWSAlgorithm.HS256))
			internalAlgName = "HMACSHA256";
			
		else if (alg.equals(JWSAlgorithm.HS384))
			internalAlgName = "HMACSHA384";
			
		else if (alg.equals(JWSAlgorithm.HS512))
			internalAlgName = "HMACSHA512";
			
		else
			throw new JOSEException("Unsupported HMAC algorithm, must be HS256, HS384 or HS512");
		
		try {
			return Mac.getInstance(internalAlgName);
			
		} catch (NoSuchAlgorithmException e) {
		
			throw new JOSEException("Unsupported HMAC algorithm: " + e.getMessage(), e);
		}
	}
}
