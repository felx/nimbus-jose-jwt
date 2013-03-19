package com.nimbusds.jose.jwk;


import java.text.ParseException;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.Requirement;


/**
 * Key type. Used to represent the {@code kty} parameter in a JSON Web Key
 * (JWK). This class is immutable.
 *
 * <p>Includes constants for the following standard key types:
 *
 * <ul>
 *     <li>{@link #EC}
 *     <li>{@link #RSA}
 *     <li>{@link #OCT}
 * </ul>
 *
 * <p>Additional key types can be defined using the constructor.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-03-19)
 */
@Immutable
public final class KeyType implements JSONAware {


	/**
	 * The key type value.
	 */
	private final String value;


	/**
	 * The implementation requirement, {@code null} if not known.
	 */
	private final Requirement requirement;


	/**
	 * Elliptic Curve (DSS) key type (recommended).
	 */
	public static final KeyType EC = new KeyType("EC", Requirement.RECOMMENDED);


	/**
	 * RSA (RFC 3447) key type (required).
	 */
	public static final KeyType RSA = new KeyType("RSA", Requirement.REQUIRED);


	/**
	 * Octet sequence key type (optional)
	 */
	public static final KeyType OCT = new KeyType("oct", Requirement.OPTIONAL);
	

	/**
	 * Creates a new key type with the specified value and implementation 
	 * requirement.
	 *
	 * @param value The key type value. Values are case sensitive. Must not
	 *              be {@code null}.
	 * @param req   The implementation requirement, {@code null} if not 
	 *              known.
	 */
	public KeyType(final String value, final Requirement req) {

		if (value == null) {
			throw new IllegalArgumentException("The key type value must not be null");
		}

		this.value = value;

		requirement = req;
	}


	/**
	 * Gets the value of this key type. Values are case sensitive.
	 *
	 * @return The key type.
	 */
	public String getValue() {

		return value;
	}


	/**
	 * Gets the implementation requirement of this key type.
	 *
	 * @return The implementation requirement, {@code null} if not known.
	 */
	public Requirement getRequirement() {

		return requirement;
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {

		return value.hashCode();
	}


	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {

		return object != null && 
		       object instanceof KeyType && 
		       this.toString().equals(object.toString());
	}


	/**
	 * Returns the string representation of this key type.
	 *
	 * @see #getValue
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {

		return value;
	}


	/**
	 * Returns the JSON string representation of this key type.
	 * 
	 * @return The JSON string representation.
	 */
	@Override
	public String toJSONString() {

		StringBuilder sb = new StringBuilder();
		sb.append('"');
		sb.append(JSONObject.escape(value));
		sb.append('"');
		return sb.toString();
	}


	/**
	 * Parses a key type from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The key type (matching standard key type constant, else a 
	 *         newly created one).
	 *
	 * @throws ParseException If the string couldn't be parsed.
	 */
	public static KeyType parse(final String s) {

		if (s == null) {
			throw new IllegalArgumentException("The ket type string must not be null");
		}

		if (s.equals(EC.getValue())) {

			return EC;

		} else if (s.equals(RSA.getValue())) {

			return RSA;

		} else if (s.equals(OCT.getValue())) {

			return OCT;

		} else {
			
			return new KeyType(s, null);
		}
	}
}
