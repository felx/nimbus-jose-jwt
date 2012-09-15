package com.nimbusds.util;


import net.minidev.json.JSONAware;
import net.minidev.json.JSONValue;


/**
 * Base64-encoded object.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-19)
 */
public class Base64 implements JSONAware {
	
	
	/**
	 * The Base64 value.
	 */
	private String value;
	
	
	/**
	 * Creates a new Base64-encoded object.
	 *
	 * @param base64 The Base64-encoded object value. The value is not 
	 *               verified for having characters from a Base64 
	 *               alphabet. Must not be {@code null}.
	 */
	public Base64(final String base64) {
	
		if (base64 == null)
			throw new NullPointerException("The Base64 value must not be null");
		
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
	 * Returns a JSON string representation of this object.
	 *
	 * @return The JSON string representation of this object.
	 */
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
	public String toString() {
	
		return value;
	}
	
	
	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
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
	public boolean equals(final Object object) {

		return object instanceof Base64 && this.toString().equals(object.toString());
	}

	
	
	/**
	 * Base64-encode the specified byte array. 
	 *
	 * @param bytes The byte array to encode. Must not be {@code null}.
	 *
	 * @return The resulting Base64 object.
	 */
	public static Base64URL encode(final byte[] bytes) {
	
		return new Base64URL(org.apache.commons.codec.binary.Base64.encodeBase64String(bytes));
	}
}
