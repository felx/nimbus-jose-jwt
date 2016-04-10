package com.nimbusds.jose.jwk.sourcing;


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;


/**
 * JSON Web Key (JWK) source. Exposes a method for retrieving selected keys for
 * a party (such as a JWT issuer). Implementations must be thread-safe.
 */
public interface JWKSource {
	

	/**
	 * Retrieves a list of JWKs matching the specified criteria.
	 *
	 * @param id          Identifier of the JWK owner, typically an
	 *                    Authorisation Server / OpenID Provider issuer ID,
	 *                    or client ID. Must not be {@code null}.
	 * @param jwkSelector A JWK selector. Must not be {@code null}.
	 *
	 * @return The matching JWKs, empty list if no matches were found or
	 *         retrieval failed.
	 */
	List<JWK> get(final String id, final JWKSelector jwkSelector);
}
