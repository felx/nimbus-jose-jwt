package com.nimbusds.jose.proc;


import net.jcip.annotations.ThreadSafe;


/**
 * Abstract JSON Web Key (JWK) selector.
 */
@ThreadSafe
public abstract class AbstractJWKSelector {


	/**
	 * Identifier for the JWK selector.
	 */
	private final String id;


	/**
	 * Creates a new abstract JWK selector.
	 *
	 * @param id Identifier for the JWK selector. Must not be {@code null}.
	 */
	public AbstractJWKSelector(final String id) {
		if (id == null) {
			throw new IllegalArgumentException("The identifier must not be null");
		}
		this.id = id;
	}


	/**
	 * Returns the the identifier for the JWK selector.
	 *
	 * @return The identifier.
	 */
	public String getIdentifier() {
		return id;
	}
}
