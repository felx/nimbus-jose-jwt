package com.nimbusds.jose;


import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;


/**
 * JOSE algorithm family name, represents the {@code alg} parameter in JSON
 * Web Keys (JWKs). This class is immutable.
 *
 * <p>Includes constants for the following standard algorithm families:
 *
 * <ul>
 *     <li>{@link #EC}
 *     <li>{@link #RSA}
 * </ul>
 *
 * <p>Additional algorithm family names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-18)
 */
public final class AlgorithmFamily implements JSONAware {


	/**
	 * The JOSE algorithm family name.
	 */
	private final String name;
	
	
	/**
	 * The implementation requirement, {@code null} if not known.
	 */
	private final Requirement requirement;
	
	
	/**
	 * Elliptic Curve (DSS) algorithm family (recommended).
	 */
	public static final AlgorithmFamily EC = new AlgorithmFamily("EC", Requirement.RECOMMENDED);
	
	
	/**
	 * RSA (RFC 3447) algorithm family (required).
	 */
	public static final AlgorithmFamily RSA = new AlgorithmFamily("RSA", Requirement.REQUIRED);
	
	
	/**
	 * Creates a new JOSE algorithm family with the specified name and 
	 * implementation requirement.
	 *
	 * @param name The JOSE algorithm family name. Names are case sensitive.
	 *             Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public AlgorithmFamily(final String name, final Requirement req) {
	
		if (name == null)
			throw new IllegalArgumentException("The algorithm family name must not be null");
		
		this.name = name;
		
		requirement = req;
	}
	
	
	/**
	 * Gets the name of this JOSE algorithm family. Names are case 
	 * sensitive.
	 *
	 * @return The JOSE algorithm family name.
	 */
	public String getName() {
	
		return name;
	}
	
	
	/**
	 * Gets the implementation requirement of this JOSE algorithm family.
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
	
		return name.hashCode();
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
	
		return object instanceof AlgorithmFamily && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Returns the string representation of this JOSE algorithm family.
	 *
	 * @see #getName
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {
	
		return name;
	}
	
	
	/**
	 * Returns the JSON string representation of this JOSE algorithm family.
	 * 
	 * @return The JSON string representation.
	 */
	@Override
	public String toJSONString() {
	
		StringBuilder sb = new StringBuilder();
		sb.append('"');
		sb.append(JSONObject.escape(name));
		sb.append('"');
		return sb.toString();
	}
	
	
	/**
	 * Parses a JOSE algorithm family from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JOSE algorithm family (matching standard algorithm 
	 *         family constant, else a newly created one).
	 *
	 * @throws ParseException If the string couldn't be parsed.
	 */
	public static AlgorithmFamily parse(final String s) {
	
		if (s == null)
			throw new IllegalArgumentException("The algorithm family string must not be null");
		
		if (s.equals(EC.getName()))
			return EC;
		
		else if (s.equals(RSA.getName()))
			return RSA;
		
		else
			return new AlgorithmFamily(s, null);
	}
}
