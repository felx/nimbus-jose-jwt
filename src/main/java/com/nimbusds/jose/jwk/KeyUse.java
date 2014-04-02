package com.nimbusds.jose.jwk;


import java.text.ParseException;


/**
 * Enumeration of public key uses. Represents the {@code use} parameter in a
 * JSON Web Key (JWK).
 *
 * <p>Public JWK use values:
 *
 * <ul>
 *     <li>{@link #SIGNATURE sig}
 *     <li>{@link #ENCRYPTION enc}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-02)
 */
public enum KeyUse {


	/**
	 * Signature.
	 */
	SIGNATURE("sig"),


	/**
	 * Encryption.
	 */
	ENCRYPTION("enc");


	/**
	 * The public key use identifier.
	 */
	private final String identifier;


	/**
	 * Creates a new public key use with the specified identifier.
	 *
	 * @param identifier The public key use identifier. Must not be
	 *                   {@code null}.
	 */
	private KeyUse(final String identifier) {

		if (identifier == null)
			throw new IllegalArgumentException("The key use identifier must not be null");

		this.identifier = identifier;
	}


	/**
	 * Returns the identifier of this public key use.
	 *
	 * @return The identifier.
	 */
	public String identifier() {

		return identifier;
	}


	/**
	 * @see #identifier()
	 */
	@Override
	public String toString() {

		return identifier();
	}


	/**
	 * Parses a public key use from the specified JWK {@code use} parameter
	 * value.
	 *
	 * @param s The string to parse. May be {@code null}.
	 *
	 * @return The public key use, {@code null} if none.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        public key use.
	 */
	public static KeyUse parse(final String s)
		throws ParseException {

		if (s == null) {
			return null;
		}

		for (KeyUse use: KeyUse.values()) {

			if (s.equals(use.identifier)) {
				return use;
			}
		}

		throw new ParseException("Invalid JWK use: " + s, 0);
	}
}
