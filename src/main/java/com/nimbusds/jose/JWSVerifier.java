package com.nimbusds.jose;


import com.nimbusds.jose.util.Base64URL;


/**
 * Interface for verifying JSON Web Signature (JWS) objects.
 *
 * <p>Callers can query the verifier to determine its algorithm capabilities as
 * well as the JWS algorithms and header parameters that are accepted for 
 * processing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
public interface JWSVerifier extends JWSAlgorithmProvider {


	/**
	 * Gets the JWS header filter associated with the verifier. Specifies the
	 * names of those {@link #supportedAlgorithms supported JWS algorithms} and 
	 * header parameters that the verifier is configured to accept.
	 *
	 * <p>Attempting to {@link #verify verify} a JWS object signature with an
	 * algorithm or header parameter that is not accepted must result in a 
	 * {@link JOSEException}.
	 *
	 * @return The JWS header filter.
	 */
	public JWSHeaderFilter getJWSHeaderFilter();
	
	
	/**
	 * Verifies the specified {@link JWSObject#getSignature signature} of a
	 * {@link JWSObject JWS object}.
	 *
	 * @param header        The JSON Web Signature (JWS) header. Must 
	 *                      specify an accepted JWS algorithm, must contain
	 *                      only accepted header parameters, and must not be
	 *                      {@code null}.
	 * @param signedContent The signed content. Must not be {@code null}.
	 * @param signature     The signature part of the JWS object. Must not
	 *                      be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully verified, else
	 *         {@code false}.
	 *
	 * @throws JOSEException If the JWS algorithm is not accepted, if a header
	 *                       parameter is not accepted, or if signature 
	 *                       verification failed for some other reason.
	 */
	public boolean verify(final ReadOnlyJWSHeader header, 
	                      final byte[] signedContent, 
	                      final Base64URL signature)
		throws JOSEException;
}
