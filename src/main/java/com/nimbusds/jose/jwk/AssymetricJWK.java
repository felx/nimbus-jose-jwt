package com.nimbusds.jose.jwk;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.nimbusds.jose.JOSEException;


/**
 * Asymmetric (pair) JSON Web Key (JWK).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-12-08
 */
public interface AssymetricJWK {
	

	/**
	 * Returns a Java public key representation of the JWK.
	 *
	 * @return The Java public key.
	 *
	 * @throws JOSEException If conversion failed.
	 */
	PublicKey toPublicKey()
		throws JOSEException;


	/**
	 * Returns a Java private key representation of this JWK.
	 *
	 * @return The Java private key, {@code null} if not specified.
	 *
	 * @throws JOSEException If conversion failed.
	 */
	PrivateKey toPrivateKey()
		throws JOSEException;


	/**
	 * Returns a Java key pair representation of this JWK.
	 *
	 * @return The Java key pair. The private key will be {@code null} if
	 *         not specified.
	 *
	 * @throws JOSEException If conversion failed.
	 */
	KeyPair toKeyPair()
		throws JOSEException;
}
