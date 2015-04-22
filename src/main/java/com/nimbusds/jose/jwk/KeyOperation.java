package com.nimbusds.jose.jwk;


import java.text.ParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


/**
 * Enumeration of key operations. Represents the {@code key_ops} parameter in a
 * JSON Web Key (JWK).
 *
 * <p>JWK operation values:
 *
 * <ul>
 *     <li>{@link #SIGN sign}
 *     <li>{@link #VERIFY verify}
 *     <li>{@link #ENCRYPT encrypt}
 *     <li>{@link #DECRYPT decrypt}
 *     <li>{@link #WRAP_KEY wrapKey}
 *     <li>{@link #UNWRAP_KEY unwrapKey}
 *     <li>{@link #DERIVE_KEY deriveKey}
 *     <li>{@link #DERIVE_BITS deriveBits}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-02)
 */
public enum KeyOperation {


	/**
	 * Compute signature or MAC.
	 */
	SIGN("sign"),


	/**
	 * Verify signature or MAC.
	 */
	VERIFY("verify"),


	/**
	 * Encrypt content.
	 */
	ENCRYPT("encrypt"),


	/**
	 * Decrypt content and validate decryption, if applicable.
	 */
	DECRYPT("decrypt"),


	/**
	 * Encrypt key.
	 */
	WRAP_KEY("wrapKey"),


	/**
	 * Decrypt key and validate decryption, if applicable.
	 */
	UNWRAP_KEY("unwrapKey"),


	/**
	 * Derive key.
	 */
	DERIVE_KEY("deriveKey"),


	/**
	 * Derive bits not to be used as a key.
	 */
	DERIVE_BITS("deriveBits");


	/**
	 * The key operation identifier.
	 */
	private final String identifier;


	/**
	 * Creates a new key operation with the specified identifier.
	 *
	 * @param identifier The key operation identifier. Must not be
	 *                   {@code null}.
	 */
	KeyOperation(final String identifier) {

		if (identifier == null)
			throw new IllegalArgumentException("The key operation identifier must not be null");

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
	 * Parses a key operation set from the specified JWK {@code key_ops}
	 * parameter value.
	 *
	 * @param sl The string list to parse. May be {@code null}.
	 *
	 * @return The key operation set, {@code null} if none.
	 *
	 * @throws ParseException If the string list couldn't be parsed to a
	 *                        valid key operation list.
	 */
	public static Set<KeyOperation> parse(final List<String> sl)
		throws ParseException {

		if (sl == null) {
			return null;
		}

		Set<KeyOperation> keyOps = new LinkedHashSet<>();

		for (String s: sl) {

			if (s == null) {
				// skip
				continue;
			}

			KeyOperation parsedOp = null;

			for (KeyOperation op: KeyOperation.values()) {

				if (s.equals(op.identifier())) {
					parsedOp = op;
					break;
				}
			}

			if (parsedOp != null) {
				keyOps.add(parsedOp);
			}
			else {
				throw new ParseException("Invalid JWK operation: " + s, 0);
			}
		}

		return keyOps;
	}
}
