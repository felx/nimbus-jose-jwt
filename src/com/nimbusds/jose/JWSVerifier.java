package com.nimbusds.jose;


import com.nimbusds.util.Base64URL;


/**
 * Interface for verifying JSON Web Signature (JWS) objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-20)
 */
public interface JWSVerifier {


	/**
	 * Verifies the specified {@link JWSObject#getSignature signature} of a
	 * {@link JWSObject JWS object}.
	 *
	 * @param header        The JSON Web Signature (JWS) header. Must not be
	 *                      {@code null}.
	 * @param signedContent The signed content. Must not be {@code null}.
	 * @param signature     The signature part of the JWS object. Must not
	 *                      be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully verified, else
         *         {@code false} if the signature was found to be invalid.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported or if
	 *                       signature verification failed for some other 
	 *                       reason.
	 */
	public boolean verify(final ReadOnlyJWSHeader header, final byte[] signedContent, final Base64URL signature)
		throws JOSEException;
}
