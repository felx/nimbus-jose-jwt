package com.nimbusds.jose.proc;


import com.nimbusds.jose.jwk.sourcing.JWKSource;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract JSON Web Key (JWK) selector with source.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-04-10
 */
@ThreadSafe
abstract class AbstractJWKSelectorWithSource <C extends SecurityContext> {
	

	/**
	 * The JWK source.
	 */
	private final JWKSource<C> jwkSource;


	/**
	 * Creates a new abstract JWK selector with a source.
	 *
	 * @param jwkSource The JWK source. Must not be {@code null}.
	 */
	public AbstractJWKSelectorWithSource(final JWKSource<C> jwkSource) {
		if (jwkSource == null) {
			throw new IllegalArgumentException("The JWK source must not be null");
		}
		this.jwkSource = jwkSource;
	}


	/**
	 * Returns the JWK source.
	 *
	 * @return The JWK source.
	 */
	public JWKSource<C> getJWKSource() {
		return jwkSource;
	}
}
