package com.nimbusds.jose;


import java.util.Set;

import com.nimbusds.jose.util.Base64URL;


/**
 * Interface for verifying JSON Web Signature (JWS) objects.
 *
 * <p>Callers can query the verifier to determine its algorithm capabilities as
 * well as the JWS algorithms and header parameters that are accepted for 
 * processing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
public interface JWSVerifier extends JWSAlgorithmProvider {


	/**
	 * Gets the names of the accepted JWS algorithms. These correspond to
	 * the {@code alg} JWS header parameter.
	 *
	 * @return The accepted JWS algorithms, as a read-only set, empty set
	 *         if none.
	 */
	public Set<JWSAlgorithm> getAcceptedAlgorithms();


	/**
	 * Sets the names of the accepted JWS algorithms. These correspond to
	 * the {@code alg} JWS header parameter.
	 *
	 * @param acceptedAlgs The accepted JWS algorithms. Must be a subset of
	 *                     the supported algorithms and not {@code null}.
	 */
	public void setAcceptedAlgorithms(final Set<JWSAlgorithm> acceptedAlgs);


	/**
	 * Gets the names of the critical JWS header parameters to ignore.
	 * These are indicated by the {@code crit} header parameter. The JWS
	 * verifier should not ignore critical headers by default.
	 *
	 * @return The names of the critical JWS header parameters to ignore,
	 *         empty or {@code null} if none.
	 */
	public Set<String> getIgnoredCriticalHeaderParameters();


	/**
	 * Sets the names of the critical JWS header parameters to ignore.
	 * These are indicated by the {@code crit} header parameter. The JWS
	 * verifier should not ignore critical headers by default. Use this
	 * setter to delegate processing of selected critical headers to the
	 * application.
	 *
	 * @param headers The names of the critical JWS header parameters to
	 *                ignore, empty or {@code null} if none.
	 */
	public void setIgnoredCriticalHeaderParameters(final Set<String> headers);


	/**
	 * Verifies the specified {@link JWSObject#getSignature signature} of a
	 * {@link JWSObject JWS object}.
	 *
	 * @param header       The JSON Web Signature (JWS) header. Must 
	 *                     specify an accepted JWS algorithm, must contain
	 *                     only accepted header parameters, and must not be
	 *                     {@code null}.
	 * @param signingInput The signing input. Must not be {@code null}.
	 * @param signature    The signature part of the JWS object. Must not
	 *                     be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully verified, 
	 *         else {@code false}.
	 *
	 * @throws JOSEException If the JWS algorithm is not accepted, if a 
	 *                       header parameter is not accepted, or if 
	 *                       signature verification failed for some other
	 *                       reason.
	 */
	public boolean verify(final JWSHeader header,
			      final byte[] signingInput,
			      final Base64URL signature)
		throws JOSEException;
}
