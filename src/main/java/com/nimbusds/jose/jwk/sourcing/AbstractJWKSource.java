package com.nimbusds.jose.jwk.sourcing;


import net.jcip.annotations.ThreadSafe;


/**
 * Abstract JSON Web Key (JWK) source.
 */
@ThreadSafe
abstract class AbstractJWKSource implements JWKSource {
	

	/**
	 * The key owner.
	 */
	private final String owner;


	/**
	 * Creates a new abstract JWK source.
	 *
	 * @param owner The key owner identifier. Typically the OAuth 2.0
	 *              server issuer ID, or client ID. Must not be
	 *              {@code null}.
	 */
	public AbstractJWKSource(final String owner) {
		if (owner == null) {
			throw new IllegalArgumentException("The owner identifier must not be null");
		}
		this.owner = owner;
	}


	/**
	 * Returns the owner identifier.
	 *
	 * @return The owner identifier.
	 */
	public String getOwner() {

		return owner;
	}
}
