package com.nimbusds.jose;


import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;


/**
 * Compression algorithm for JSON Web Encryption (JWE).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-17)
 */
public final class CompressionAlgorithm implements JSONAware {
	
	
	/**
	 * DEFLATE Compressed Data Format Specification version 1.3, as 
	 * described in RFC 1951.
	 */
	public static final CompressionAlgorithm DEF = new CompressionAlgorithm("DEF");
	
	
	/**
	 * The algorithm name.
	 */
	private String name;
	
	
	/**
	 * Creates a new compression algorithm with the specified name.
	 *
	 * @param name The compression algorithm name. Must not be {@code null}.
	 */
	public CompressionAlgorithm(final String name) {
	
		if (name == null)
			throw new IllegalArgumentException("The compression algorithm name must not be null");
		
		this.name = name;
	}
	
	
	/**
	 * Gets the name of this compression algorithm.
	 *
	 * @return The compression algorithm name.
	 */
	public String getName() {
	
		return name;
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
	
		return object instanceof CompressionAlgorithm && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Returns the string representation of this compression algorithm.
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
	 * Returns the JSON string representation of this compression algorithm.
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
	
	
// 	/**
// 	 * Parses the specified compression algorithm.
// 	 *
// 	 * @param name The canonical compression algorithm name. Must not be
// 	 *             {@code null}.
// 	 *
// 	 * @throws ParseException If the name is {@code null} of doesn't match a
// 	 *                        compression algorithm name.
// 	 */
// 	public static CompressionAlgorithm parse(final String name)
// 		throws ParseException {
// 		
// 		if (name == null)
// 			throw new ParseException("The compression algorithm name must not be null", 0);
// 		
// 		if (name.equals("DEF"))
// 			return DEF;
// 			
// 		else if (name.equals("none"))
// 			return NONE;
// 			
// 		else
// 			throw new ParseException("Unknown compression algorithm: " + name, 0);
// 	}
}
