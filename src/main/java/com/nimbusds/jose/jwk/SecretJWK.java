package com.nimbusds.jose.jwk;


import javax.crypto.SecretKey;


/**
 * Secret (symmetric) JSON Web Key (JWK).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-12-08
 */
public interface SecretJWK {
	

	/**
	 * Returns a Java secret key representation of the JWK.
	 *
	 * @return The Java secret key.
	 */
	SecretKey toSecretKey();
}
