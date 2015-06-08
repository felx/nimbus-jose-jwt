package com.nimbusds.jose.handler;


import java.security.Key;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;


/**
 * JSON Web Signature (JWS) verifier factory.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-08)
 */
public interface JWSVerifierFactory {


	/**
	 * Creates a new JWS verifier for the specified header and key.
	 *
	 * @param header The JWS header. Not {@code null}.
	 * @param key    The key intended to verify the JWS message. Not
	 *               {@code null}.
	 *
	 * @return The JWS verifier.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported or the
	 *                       key type doesn't match the expected for the
	 *                       JWS algorithm.
	 */
	JWSVerifier createJWSVerifier(final JWSHeader header, final Key key)
		throws JOSEException;
}
