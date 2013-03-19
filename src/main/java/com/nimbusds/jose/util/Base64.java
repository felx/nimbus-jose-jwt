package com.nimbusds.jose.util;


import java.math.BigInteger;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONValue;


/**
 * Base64-encoded object.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-19)
 */
@Immutable
public class Base64 implements JSONAware {


	/**
	 * The Base64 value.
	 */
	private final String value;


	/**
	 * Creates a new Base64-encoded object.
	 *
	 * @param base64 The Base64-encoded object value. The value is not 
	 *               validated for having characters from a Base64 
	 *               alphabet. Must not be {@code null}.
	 */
	public Base64(final String base64) {

		if (base64 == null) {
			throw new IllegalArgumentException("The Base64 value must not be null");
		}

		value = base64;
	}


	/**
	 * Decodes this Base64 object to a byte array.
	 *
	 * @return The resulting byte array.
	 */
	public byte[] decode() {

		return org.apache.commons.codec.binary.Base64.decodeBase64(value);
	}


	/**
	 * Decodes this Base64 object to an unsigned big integer.
	 *
	 * <p>Same as {@code new BigInteger(1, base64.decode())}.
	 *
	 * @return The resulting unsigned big integer.
	 */
	public BigInteger decodeToBigInteger() {

		return new BigInteger(1, decode());
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
	 * Returns a Base64 string representation of this object. The string 
	 * will be chunked into 76 character blocks separated by CRLF.
	 *
	 * @return The Base64 string representation, chunked into 76 character 
	 *         blocks separated by CRLF.
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
		       object instanceof Base64 && 
		       this.toString().equals(object.toString());
	}


	/**
	 * Base64-encode the specified byte array. 
	 *
	 * @param bytes The byte array to encode. Must not be {@code null}.
	 *
	 * @return The resulting Base64 object.
	 */
	public static Base64 encode(final byte[] bytes) {

		return new Base64(org.apache.commons.codec.binary.Base64.encodeBase64String(bytes));
	}


	/**
	 * Base64-encode the specified big integer.
	 *
	 * @param bigInt The big integer to encode. Must not be {@code null}.
	 *
	 * @return The resulting Base64 object.
	 */
	public static Base64 encode(final BigInteger bigInt) {

		return encode(bigInt.toByteArray());
	}
}
