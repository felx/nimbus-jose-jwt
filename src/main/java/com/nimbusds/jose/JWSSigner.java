package com.nimbusds.jose;


import com.nimbusds.jose.util.Base64URL;


/**
 * Interface for signing JSON Web Signature (JWS) objects.
 *
 * <p>Callers can query the signer to determine its algorithm capabilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public interface JWSSigner extends JWSAlgorithmProvider {


	/**
	 * Signs the specified {@link JWSObject#getSignableContent signable 
	 * content} of a {@link JWSObject JWS object}.
	 *
	 * @param header          The JSON Web Signature (JWS) header. Must 
	 *                        specify a supported JWS algorithm and must not
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
