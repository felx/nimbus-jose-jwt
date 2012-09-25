package com.nimbusds.jose.sdk;


import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;


/**
 * JOSE object type, represents the {@code typ} header parameter in plain, JSON
 * Web Signature (JWS) and JSON Web Encryption (JWE) objects. This class is 
 * immutable.
 *
 * <p>Includes constants for the following standard types:
 *
 * <ul>
 *     <li>{@link #JWS}
 *     <li>{@link #JWE}
 * </ul>
 *
 * <p>Additional types can be defined using the constructor.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-17)
 */
public final class JOSEObjectType implements JSONAware {


	/**
	 * JWS object type.
	 */
	public static final JOSEObjectType JWS = new JOSEObjectType("JWS");
	
	
	/**
	 * JWE object type.
	 */
	public static final JOSEObjectType JWE = new JOSEObjectType("JWE");
	
	
	/**
	 * The object type.
	 */
	private final String type;
	
	
	/**
	 * Creates a new JOSE object type.
	 *
	 * @param type The object type. Must not be {@code null}.
	 */
	public JOSEObjectType(final String type) {
	
		if (type == null)
			throw new IllegalArgumentException("The object type must not be null");
		
		this.type = type;
	}
	
	
	/**
	 * Gets the JOSE object type.
	 *
	 * @return The JOSE object type.
	 */
	public String getType() {
	
		return type;
	}
	
	
	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {
	
		return type.hashCode();
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
	
		return object instanceof JOSEObjectType && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Returns the string representation of this JOSE object type.
	 *
	 * @see #getType
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {
	
		return type;
	}
	
	
	/**
	 * Returns the JSON string representation of this JOSE object type.
	 * 
	 * @return The JSON string representation.
	 */
	@Override
	public String toJSONString() {
	
		StringBuilder sb = new StringBuilder();
		sb.append('"');
		sb.append(JSONObject.escape(type));
		sb.append('"');
		return sb.toString();
	}
}
