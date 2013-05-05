package com.nimbusds.jose;


import net.jcip.annotations.Immutable;


/**
 * Encryption method name, represents the {@code enc} header parameter in JSON
 * Web Encryption (JWE) objects. This class is immutable.
 *
 * <p>Includes constants for the following standard encryption method names:
 *
 * <ul>
 *     <li>{@link #A128CBC_HS256 A128CBC-HS256}
 *     <li>{@link #A256CBC_HS512 A256CBC-HS512}
 *     <li>{@link #A128GCM}
 *     <li>{@link #A256GCM}
 * </ul>
 *
 * <p>Additional encryption method names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-05)
 */
@Immutable
public final class EncryptionMethod extends Algorithm {


	/**
	 * The Content Encryption Key (CEK) bit length, zero if not specified.
	 */
	private final int cekBitLength;


	/**
	 * AES_128_CBC_HMAC_SHA_256 authenticated encryption using a 256 bit 
	 * key (required).
	 */
	public static final EncryptionMethod A128CBC_HS256 = 
		new EncryptionMethod("A128CBC-HS256", Requirement.REQUIRED, 256);


	/**
	 * AES_256_CBC_HMAC_SHA_512 authenticated encryption using a 512 bit
	 * key (required).
	 */
	public static final EncryptionMethod A256CBC_HS512 = 
		new EncryptionMethod("A256CBC-HS512", Requirement.REQUIRED, 512);


	/**
	 * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 128 bit key 
	 * (recommended).
	 */
	public static final EncryptionMethod A128GCM = 
		new EncryptionMethod("A128GCM", Requirement.RECOMMENDED, 128);


	/**
	 * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 256 bit key 
	 * (recommended).
	 */
	public static final EncryptionMethod A256GCM = 
		new EncryptionMethod("A256GCM", Requirement.RECOMMENDED, 256);


	/**
	 * Creates a new encryption method.
	 *
	 * @param name         The encryption method name. Must not be 
	 *                     {@code null}.
	 * @param req          The implementation requirement, {@code null} if 
	 *                     not known.
	 * @param cekBitLength The Content Encryption Key (CEK) bit length, 
	 *                     zero if not specified.
	 */
	public EncryptionMethod(final String name, final Requirement req, final int cekBitLength) {

		super(name, req);

		this.cekBitLength = cekBitLength;
	}


	/**
	 * Creates a new encryption method. The Content Encryption Key (CEK)
	 * bit length is not specified.
	 *
	 * @param name The encryption method name. Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public EncryptionMethod(final String name, final Requirement req) {

		this(name, req, 0);
	}


	/**
	 * Creates a new encryption method. The implementation requirement and
	 * the Content Encryption Key (CEK) bit length are not specified.
	 *
	 * @param name The encryption method name. Must not be {@code null}.
	 */
	public EncryptionMethod(final String name) {

		this(name, null, 0);
	}


	/**
	 * Gets the length of the associated Content Encryption Key (CEK).
	 *
	 * @return The Content Encryption Key (CEK) bit length, zero if not 
	 *         specified.
	 */
	public int cekBitLength() {

		return cekBitLength;
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

		if (s.equals(A128CBC_HS256.getName())) {

			return A128CBC_HS256;

		} else if (s.equals(A256CBC_HS512.getName())) {

			return A256CBC_HS512;

		} else if (s.equals(A128GCM.getName())) {

			return A128GCM;

		} else if (s.equals(A256GCM.getName())) {

			return A256GCM;

		} else {

			return new EncryptionMethod(s);
		}
	}
}
