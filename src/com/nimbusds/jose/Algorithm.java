package com.nimbusds.jose;


import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;


/**
 * Algorithm name, with optional implementation requirement.
 *
 * @author Vladimir Dzhuvinov 
 * @version $version$ (2012-09-19)
 */
public class Algorithm implements JSONAware {
		 
		 
	/**
	 * No algorithm (plain JOSE object).
	 */
	public static final Algorithm NONE = new Algorithm("none", Requirement.REQUIRED);
	
	
	/**
	 * The algorithm name.
	 */
	private final String name;
	
	
	/**
	 * The implementation requirement, {@code null} if not known.
	 */
	private final Requirement requirement;
	
	
	/**
	 * Creates a new JOSE algorithm name.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public Algorithm(final String name, final Requirement req) {
	
		if (name == null)
			throw new IllegalArgumentException("The algorithm name must not be null");
		
		this.name = name;
		
		requirement = req;
	}
	
	
	/**
	 * Creates a new JOSE algorithm name.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 */
	public Algorithm(final String name) {
	
		this(name, null);
	}
	
	
	/**
	 * Gets the name of this algorithm.
	 *
	 * @return The algorithm name.
	 */
	public String getName() {
	
		return name;
	}
	
	
	/**
	 * Gets the implementation requirement of this algorithm.
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
	
		return object instanceof Algorithm && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Returns the string representation of this algorithm.
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
	 * Returns the JSON string representation of this algorithm.
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
}
