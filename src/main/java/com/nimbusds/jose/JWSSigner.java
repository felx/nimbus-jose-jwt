package com.nimbusds.jose;


import com.nimbusds.jose.util.Base64URL;


/**
 * JSON Web Signature (JWS) signer.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-21)
 */
public interface JWSSigner extends JWSAlgorithmProvider {


	/**
	 * Signs the specified {@link JWSObject#getSigningInput input} of a 
	 * {@link JWSObject JWS object}.
	 *
	 * @param header       The JSON Web Signature (JWS) header. Must 
	 *                     specify a supported JWS algorithm and must not 
	 *                     be {@code null}.
	 * @param signingInput The input to sign. Must not be {@code null}.
	 *
	 * @return The resulting signature part (third part) of the JWS object.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported, if a
	 *                       critical header parameter is not supported or
	 *                       marked for deferral to the application, or if
	 *                       signing failed for some other internal reason.
	 */
	Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException;
}
