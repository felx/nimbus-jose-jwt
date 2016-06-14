package com.nimbusds.jose.jwk.source;


import java.io.IOException;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * JSON Web Key (JWK) source. Exposes a method for retrieving JWKs matching a
 * specified selector. An optional context parameter is available to facilitate
 * passing of additional data between the caller and the underlying JWK source
 * (in both directions). Implementations must be thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-06-14
 */
public interface JWKSource <C extends SecurityContext> {
	

	/**
	 * Retrieves a list of JWKs matching the specified selector.
	 *
	 * @param jwkSelector A JWK selector. Must not be {@code null}.
	 * @param context     Optional context, {@code null} if not required.
	 *
	 * @return The matching JWKs, empty list if no matches were found.
	 *
	 * @throws IOException If retrieval failed.
	 */
	List<JWK> get(final JWKSelector jwkSelector, final C context)
		throws IOException;
}
