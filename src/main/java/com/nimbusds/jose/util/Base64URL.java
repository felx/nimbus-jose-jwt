package com.nimbusds.jose.util;


import java.io.UnsupportedEncodingException;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONValue;

import org.apache.commons.codec.binary.Base64;


/**
 * Base64URL-encoded object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 4648.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@Immutable
public class Base64URL implements JSONAware {


	/**
	 * UTF-8 is the required charset for all JWTs.
	 */
	private static final String CHARSET = "utf-8";


	/**
	 * The Base64URL value.
	 */
	private final String value;


	/**
	 * Creates a new Base64URL-encoded object.
	 *
	 * @param base64URL The Base64URL-encoded object value. The value is not
	 *                  validated for having characters from a Base64URL 
	 *                  alphabet. Must not be {@code null}.
	 */
	public Base64URL(final String base64URL) {

		if (base64URL == null) {
			throw new IllegalArgumentException("The Base64URL value must not be null");
		}

		value = base64URL;
	}


	/**
	 * Decodes this Base64URL object to a byte array.
	 *
	 * @return The resulting byte array.
	 */
	public byte[] decode() {

		return Base64.decodeBase64(value);
	}


	/**
	 * Decodes this Base64URL object to a string.
	 *
	 * @return The resulting string, in the UTF-8 character set.
	 */
	public String decodeToString() {

		try {
			return new String(decode(), CHARSET);

		} catch (UnsupportedEncodingException e) {

			// UTF-8 should always be supported
			return "";
		}
	}


	/**
	 * Returns a JSON string representation of this object.
	 *
	 * @return The JSON string representation of this object.
	 */
	@Override
	public String toJSONString() {

		return "\"" + JSONValue.escape(value) + "\"";
	}


	/**
	 * Returns a Base64URL string representation of this object.
	 *
	 * @return The Base64URL string representation.
	 */
	@Override
	public String toString() {

		return value;
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
				object instanceof Base64URL && 
				this.toString().equals(object.toString());
	}


	/**
	 * Base64URL-encode the specified string.
	 *
	 * @param text The string to encode. Must be in the UTF-8 character set
	 *             and not {@code null}.
	 *
	 * @return The resulting Base64URL object.
	 */
	public static Base64URL encode(final String text) {

		try {
			return encode(text.getBytes(CHARSET));

		} catch (UnsupportedEncodingException e) {

			// UTF-8 should always be supported
			return null;
		}
	}


	/**
	 * Base64URL-encode the specified byte array.
	 *
	 * @param bytes The byte array to encode. Must not be {@code null}.
	 *
	 * @return The resulting Base64URL object.
	 */
	public static Base64URL encode(final byte[] bytes) {

		return new Base64URL(Base64.encodeBase64URLSafeString(bytes));
	}
}
