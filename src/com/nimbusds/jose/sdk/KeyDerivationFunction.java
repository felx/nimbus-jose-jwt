package com.nimbusds.jose.sdk;


/**
 * Key derivation function (KDF) name, represents the {@code kdf} header 
 * parameter in JSON Web Encryption (JWE) objects. This class is immutable.
 *
 * <p>Includes constants for the following standard KDF names:
 *
 * <ul>
 *     <li>{@link #CS256}
 *     <li>{@link #CS384}
 *     <li>{@link #CS512}
 * </ul>
 *
 * <p>Additional KDF names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public final class KeyDerivationFunction extends Algorithm {


	/**
	 * Concat KDF, as defined in section 5.8.1 of NIST.800-56A, with
	 * parameters per section 4.13, using SHA-256 as the digest method
	 * (required).
	 */
	public static final KeyDerivationFunction CS256 = new KeyDerivationFunction("CS256", Requirement.REQUIRED);
	
	
	/**
	 * Concat KDF, as defined in section 5.8.1 of NIST.800-56A, with
	 * parameters per section 4.13, using SHA-384 as the digest method
	 * (optional).
	 */
	public static final KeyDerivationFunction CS384 = new KeyDerivationFunction("CS384", Requirement.OPTIONAL);
	
	
	/**
	 * Concat KDF, as defined in section 5.8.1 of NIST.800-56A, with
	 * parameters per section 4.13, using SHA-512 as the digest method
	 * (optional).
	 */
	public static final KeyDerivationFunction CS512 = new KeyDerivationFunction("CS512", Requirement.OPTIONAL);
	
	
	/**
	 * Creates a new key derivation function.
	 *
	 * @param name The key derivation function name. Must not be 
	 *             {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public KeyDerivationFunction(final String name, final Requirement req) {
	
		super(name, req);
	}
	
	
	/**
	 * Creates a new key derivation function.
	 *
	 * @param name The key derivation function name. Must not be 
	 *             {@code null}.
	 */
	public KeyDerivationFunction(final String name) {
	
		super(name, null);
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof KeyDerivationFunction && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses a key derivation function from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The key derivation function.
	 */
	public static KeyDerivationFunction parse(final String s) {
	
		if (s == CS256.getName())
			return CS256;
		
		else if (s == CS384.getName())
			return CS384;
		
		else if (s == CS512.getName())
			return CS512;
		
		else
			return new KeyDerivationFunction(s);
	}
}