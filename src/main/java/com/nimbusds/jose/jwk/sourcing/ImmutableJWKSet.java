package com.nimbusds.jose.jwk.sourcing;


import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import net.jcip.annotations.Immutable;


/**
 * Immutable JSON Web Key (JWK) set. Intended for a JWK set specified by value.
 */
@Immutable
public class ImmutableJWKSet extends AbstractJWKSource {


	/**
	 * The JWK set.
	 */
	private final JWKSet jwkSet;


	/**
	 * Creates a new immutable JWK set.
	 *
	 * @param id     The JWK set owner identifier. Typically the OAuth 2.0
	 *               server issuer ID, or client ID. Must not be
	 *               {@code null}.
	 * @param jwkSet The JWK set. Must not be {@code null}.
	 */
	public ImmutableJWKSet(final String id, final JWKSet jwkSet) {
		super(id);
		if (jwkSet == null) {
			throw new IllegalArgumentException("The JWK set must not be null");
		}
		this.jwkSet = jwkSet;
	}


	/**
	 * Returns the JWK set.
	 *
	 * @return The JWK set.
	 */
	public JWKSet getJWKSet() {
		return jwkSet;
	}


	@Override
	public List<JWK> get(final String id, final JWKSelector jwkSelector) {
		if (! getOwner().equals(id)) {
			return Collections.emptyList();
		}
		return jwkSelector.select(jwkSet);
	}
}
