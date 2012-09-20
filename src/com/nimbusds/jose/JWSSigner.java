package com.nimbusds.jose;


import com.nimbusds.util.Base64URL;


/**
 * Interface for signing JSON Web Signature (JWS) objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-20)
 */
public interface JWSSigner {


	/**
	 * Signs the specified {@link JWSObject#getSignableContent signable 
	 * content} of a {@link JWSObject JWS object}.
	 *
	 * @param header          The JSON Web Signature (JWS) header. Must not
	 *                        be {@code null}.
	 * @param signableContent The content to sign. Must not be {@code null}.
	 *
	 * @return The resulting signature part (third part) of the JWS object.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported or if
	 *                       signing failed for some other reason.
	 */
	public Base64URL sign(final ReadOnlyJWSHeader header, final byte[] signableContent)
		throws JOSEException;
}
