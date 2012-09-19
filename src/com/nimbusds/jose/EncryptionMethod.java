package com.nimbusds.jose;


/**
 * Encryption method, used in JSON Web Encryption (JWE), with optional 
 * implementation requirement. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public final class EncryptionMethod extends Algorithm {


	/**
	 * Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC)
	 * mode with PKCS #5 padding (NIST.800-38A) using 128 bit keys.
	 */
	public static final EncryptionMethod A128CBC = new EncryptionMethod("A128CBC", Requirement.REQUIRED);
	
	
	/**
	 * Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC)
	 * mode with PKCS #5 padding (NIST.800-38A) using 256 bit keys.
	 */
	public static final EncryptionMethod A256CBC = new EncryptionMethod("A256CBC", Requirement.REQUIRED);
	
	
	/**
	 * Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
	 * (NIST.800-38D) using 128 bit keys.
	 */
	public static final EncryptionMethod A128GCM = new EncryptionMethod("A128GCM", Requirement.RECOMMENDED);
	
	
	/**
	 * Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
	 * (NIST.800-38D) using 256 bit keys.
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
}
