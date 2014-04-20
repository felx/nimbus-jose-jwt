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
 * @version $version$ (2014-04-20)
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
	public void setAcceptedAlgorithms(Set<JWSAlgorithm> acceptedAlgs);


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
	public boolean verify(final ReadOnlyJWSHeader header, final byte[] signingInput, final Base64URL signature)
		throws JOSEException;
}
