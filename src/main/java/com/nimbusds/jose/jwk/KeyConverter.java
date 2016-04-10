package com.nimbusds.jose.jwk;


import java.security.Key;
import java.security.KeyPair;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.JOSEException;


/**
 * Key converter.
 */
public class KeyConverter {
	

	/**
	 * Converts the specified list of JSON Web Keys (JWK) their standard
	 * Java class representation. Asymmetric {@link RSAKey RSA} and
	 * {@link ECKey EC key} pairs are converted to
	 * {@link java.security.PublicKey} and {@link java.security.PrivateKey}
	 * (if specified) objects. {@link OctetSequenceKey secret JWKs} are
	 * converted to {@link javax.crypto.SecretKey} objects. Key conversion
	 * exceptions are silently ignored.
	 *
	 * @param jwkList The JWK list. May be {@code null}.
	 *
	 * @return The converted keys, empty set if none or {@code null}.
	 */
	public static List<Key> toJavaKeys(final List<JWK> jwkList) {

		if (jwkList == null) {
			return Collections.emptyList();
		}

		List<Key> out = new LinkedList<>();
		for (JWK jwk: jwkList) {
			try {
				if (jwk instanceof AssymetricJWK) {
					KeyPair keyPair = ((AssymetricJWK)jwk).toKeyPair();
					out.add(keyPair.getPublic()); // add public
					if (keyPair.getPrivate() != null) {
						out.add(keyPair.getPrivate()); // add private if present
					}
				} else if (jwk instanceof SecretJWK) {
					out.add(((SecretJWK)jwk).toSecretKey());
				}
			} catch (JOSEException e) {
				// ignore and continue
			}
		}
		return out;
	}
}
