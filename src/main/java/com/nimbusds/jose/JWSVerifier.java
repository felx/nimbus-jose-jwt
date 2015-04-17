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
 * @version $version$ (2015-04-17)
 */
public interface JWSVerifier extends JWSAlgorithmProvider {


	/**
	 * Returns the employed JWS header validator.
	 *
	 * @return The JWS header validator.
	 */
	JWSHeaderValidator getHeaderValidator();


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
	boolean verify(final JWSHeader header, final byte[] signingInput, final Base64URL signature)
		throws JOSEException;
}
