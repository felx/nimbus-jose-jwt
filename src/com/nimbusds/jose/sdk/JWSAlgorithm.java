package com.nimbusds.jose.sdk;


/**
 * JSON Web Signature (JWS) algorithm name, represents the {@code alg} header
 * parameter in JWS objects. Also used to represent integrity algorithm 
 * ({@code ia}) header parameters in JWE objects. This class is immutable.
 *
 * <p>Includes constants for the following standard JWS algorithm names:
 *
 * <ul>
 *     <li>{@link #HS256}
 *     <li>{@link #HS384}
 *     <li>{@link #HS512}
 *     <li>{@link #RS256}
 *     <li>{@link #RS384}
 *     <li>{@link #RS512}
 *     <li>{@link #ES256}
 *     <li>{@link #ES384}
 *     <li>{@link #ES512}
 * </ul>
 *
 * <p>Additional JWS algorithm names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public final class JWSAlgorithm extends Algorithm {


	/**
	 * HMAC using SHA-256 hash algorithm (required).
	 */
	public static final JWSAlgorithm HS256 = new JWSAlgorithm("HS256", Requirement.REQUIRED);
	
	
	/**
	 * HMAC using SHA-384 hash algorithm (optional).
	 */
	public static final JWSAlgorithm HS384 = new JWSAlgorithm("HS384", Requirement.OPTIONAL);
	
	
	/**
	 * HMAC using SHA-512 hash algorithm (optional).
	 */
	public static final JWSAlgorithm HS512 = new JWSAlgorithm("HS512", Requirement.OPTIONAL);
	
	
	/**
	 * RSA using SHA-256 hash algorithm (recommended).
	 */
	public static final JWSAlgorithm RS256 = new JWSAlgorithm("RS256", Requirement.RECOMMENDED);
	
	
	/**
	 * RSA using SHA-384 hash algorithm (optional).
	 */
	public static final JWSAlgorithm RS384 = new JWSAlgorithm("RS384", Requirement.OPTIONAL);
	
	
	/**
	 * RSA using SHA-512 hash algorithm (optional).
	 */
	public static final JWSAlgorithm RS512 = new JWSAlgorithm("RS512", Requirement.OPTIONAL);
	
	
	/**
	 * ECDSA using P-256 curve and SHA-256 hash algorithm (recommended).
	 */
	public static final JWSAlgorithm ES256 = new JWSAlgorithm("ES256", Requirement.RECOMMENDED);
	
	
	/**
	 * ECDSA using P-384 curve and SHA-384 hash algorithm (optional).
	 */
	public static final JWSAlgorithm ES384 = new JWSAlgorithm("ES384", Requirement.OPTIONAL);
	
	
	/**
	 * ECDSA using P-521 curve and SHA-512 hash algorithm (optional).
	 */
	public static final JWSAlgorithm ES512 = new JWSAlgorithm("ES512", Requirement.OPTIONAL);
	

	/**
	 * Creates a new JSON Web Signature (JWS) algorithm name.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public JWSAlgorithm(final String name, final Requirement req) {
	
		super(name, req);
	}
	
	
	/**
	 * Creates a new JSON Web Signature (JWS) algorithm name.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 */
	public JWSAlgorithm(final String name) {
	
		super(name, null);
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof JWSAlgorithm && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses a JWS algorithm from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JWS algorithm (matching standard algorithm constant, else
	 *         a newly created algorithm).
	 */
	public static JWSAlgorithm parse(final String s) {
		
		if (s == HS256.getName())
			return HS256;
		
		else if (s == HS384.getName())
			return HS384;
			
		else if (s == HS512.getName())
			return HS512;
		
		else if (s == RS256.getName())
			return RS256;
		
		else if (s == RS384.getName())
			return RS384;
		
		else if (s == RS512.getName())
			return RS512;
		
		else if (s == ES256.getName())
			return ES256;
		
		else if (s == ES384.getName())
			return ES384;
		
		else if (s == ES512.getName())
			return ES512;
		
		else
			return new JWSAlgorithm(s);
	}
}
