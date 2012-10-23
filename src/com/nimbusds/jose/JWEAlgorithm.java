package com.nimbusds.jose;


import net.jcip.annotations.Immutable;


/**
 * JSON Web Encryption (JWE) algorithm name, represents the {@code alg} header 
 * parameter in JWE objects. This class is immutable.
 *
 * <p>Includes constants for the following standard JWE algorithm names:
 *
 * <ul>
 *     <li>{@link #RSA1_5}
 *     <li>{@link #RSA_OAEP RSA-OAEP}
 *     <li>{@link #A128KW}
 *     <li>{@link #A256KW}
 *     <li>{@link #DIR dir}
 *     <li>{@link #ECDH_ES ECDH-ES}
 *     <li>{@link #ECDH_ES_A128KW ESDH-ES+A128KW}
 *     <li>{@link #ECDH_ES_A256KW ESDH-ES+A256KW}
 * </ul>
 *
 * <p>Additional JWE algorithm names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
@Immutable
public final class JWEAlgorithm extends Algorithm {


	/**
	 * RSAES-PKCS1-V1_5 (RFC 3447) (required).
	 */
	public static final JWEAlgorithm RSA1_5 = new JWEAlgorithm("RSA1_5", Requirement.REQUIRED);
	
	
	/**
	 * RSAES using Optimal Assymetric Encryption Padding (OAEP) (RFC 3447),
	 * with the default parameters specified by RFC 3447 in section A.2.1
	 * (recommended).
	 */
	public static final JWEAlgorithm RSA_OAEP = new JWEAlgorithm("RSA-OAEP", Requirement.RECOMMENDED);
	
	
	/**
	 * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) 
	 * using 256 bit keys (recommended).
	 */
	public static final JWEAlgorithm A128KW = new JWEAlgorithm("A128KW", Requirement.RECOMMENDED);
	
	
	/**
	 * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) 
	 * using 256 bit keys (recommended).
	 */
	public static final JWEAlgorithm A256KW = new JWEAlgorithm("A256KW", Requirement.RECOMMENDED);
	
	
	/**
	 * Direct use of a shared symmetric key as the Content Master Key (CMK)
	 * for the block encryption step (rather than using the symmetric key to
	 * wrap the CMK) (recommended).
	 */
	public static final JWEAlgorithm DIR = new JWEAlgorithm("dir", Requirement.RECOMMENDED);
	
	
	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Statis (RFC 6090) key 
	 * agreement using the Concat KDF, as defined in section 5.8.1 of
	 * NIST.800-56A, where the Digest Method is SHA-256 and all OtherInfo
	 * parameters the empty bit string, with the agreed-upon key being used
	 * directly as the Content Master Key (CMK) (rather than being used to
	 * wrap the CMK) (recommended).
	 */
	public static final JWEAlgorithm ECDH_ES = new JWEAlgorithm("ECDH-ES", Requirement.RECOMMENDED);
	
	
	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
	 * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
	 * Master Key (CMK) with the "A128KW" function (rather than being used
	 * directly as the CMK) (recommended).
	 */
	public static final JWEAlgorithm ECDH_ES_A128KW = new JWEAlgorithm("ECDH-ES+A128KW", Requirement.RECOMMENDED);
	
	
	/**
	 * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
	 * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
	 * Master Key (CMK) with the "A256KW" function (rather than being used
	 * directly as the CMK) (recommended).
	 */
	public static final JWEAlgorithm ECDH_ES_A256KW = new JWEAlgorithm("ECDH-ES+A256KW", Requirement.RECOMMENDED);
	
	

	/**
	 * Creates a new JSON Web Encryption (JWE) algorithm.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public JWEAlgorithm(final String name, final Requirement req) {
	
		super(name, req);
	}
	
	
	/**
	 * Creates a new JSON Web Encryption (JWE) algorithm.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 */
	public JWEAlgorithm(final String name) {
	
		super(name, null);
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof JWEAlgorithm && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses a JWE algorithm from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JWE algorithm (matching standard algorithm constant, else
	 *         a newly created algorithm).
	 */
	public static JWEAlgorithm parse(final String s) {
	
		if (s == RSA1_5.getName())
			return RSA1_5;
		
		else if (s == RSA_OAEP.getName())
			return RSA_OAEP;
		
		else if (s == A128KW.getName())
			return A128KW;
		
		else if (s == A256KW.getName())
			return A256KW;
		
		else if (s == DIR.getName())
			return DIR;
		
		else if (s == ECDH_ES.getName())
			return ECDH_ES;
		
		else if (s == ECDH_ES_A128KW.getName())
			return ECDH_ES_A128KW;
		
		else if (s == ECDH_ES_A256KW.getName())
			return ECDH_ES_A256KW;
		
		else
			return new JWEAlgorithm(s);
	}
}
