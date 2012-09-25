package com.nimbusds.jose.sdk;


/**
 * Encryption method name, represents the {@code enc} header parameter in JSON
 * Web Encryption (JWE) objects. This class is immutable.
 *
 * <p>Includes constants for the following standard encryption method names:
 *
 * <ul>
 *     <li>{@link #A128CBC}
 *     <li>{@link #A256CBC}
 *     <li>{@link #A128GCM}
 *     <li>{@link #A256GCM}
 * </ul>
 *
 * <p>Additional encryption method names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public final class EncryptionMethod extends Algorithm {


	/**
	 * Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC)
	 * mode with PKCS #5 padding (NIST.800-38A) using 128 bit keys
	 * (required).
	 */
	public static final EncryptionMethod A128CBC = new EncryptionMethod("A128CBC", Requirement.REQUIRED);
	
	
	/**
	 * Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC)
	 * mode with PKCS #5 padding (NIST.800-38A) using 256 bit keys
	 * (required).
	 */
	public static final EncryptionMethod A256CBC = new EncryptionMethod("A256CBC", Requirement.REQUIRED);
	
	
	/**
	 * Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
	 * (NIST.800-38D) using 128 bit keys (recommended).
	 */
	public static final EncryptionMethod A128GCM = new EncryptionMethod("A128GCM", Requirement.RECOMMENDED);
	
	
	/**
	 * Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
	 * (NIST.800-38D) using 256 bit keys (recommended).
	 */
	public static final EncryptionMethod A256GCM = new EncryptionMethod("A256GCM", Requirement.RECOMMENDED);
	
	
	/**
	 * Creates a new encryption method.
	 *
	 * @param name The encryption method name. Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public EncryptionMethod(final String name, final Requirement req) {
	
		super(name, req);
	}
	
	
	/**
	 * Creates a new encryption method.
	 *
	 * @param name The encryption method name. Must not be {@code null}.
	 */
	public EncryptionMethod(final String name) {
	
		super(name, null);
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof EncryptionMethod && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an encryption method from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The encryption method  (matching standard algorithm constant,
	 *         else a newly created algorithm).
	 */
	public static EncryptionMethod parse(final String s) {
	
		if (s == A128CBC.getName())
			return A128CBC;
		
		else if (s == A256CBC.getName())
			return A256CBC;
		
		else if (s == A128GCM.getName())
			return A128GCM;
		
		else if (s == A256GCM.getName())
			return A256GCM;
		
		else
			return new EncryptionMethod(s);
	}
}
