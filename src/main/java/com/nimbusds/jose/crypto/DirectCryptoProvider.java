package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;


/**
 * The base abstract class for direct encrypters and decrypters of
 * {@link com.nimbusds.jose.JWEObject JWE objects} with a shared symmetric key.
 *
 * <p>Supports the following JSON Web Algorithm (JWA):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#DIR}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-15)
 */
abstract class DirectCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {

		Set<JWEAlgorithm> algs = new HashSet<JWEAlgorithm>();
		algs.add(JWEAlgorithm.DIR);
		SUPPORTED_ALGORITHMS = algs;

		Set<EncryptionMethod> methods = new HashSet<EncryptionMethod>();
		methods.add(EncryptionMethod.A128CBC_HS256);
		methods.add(EncryptionMethod.A256CBC_HS512);
		methods.add(EncryptionMethod.A128GCM);
		methods.add(EncryptionMethod.A256GCM);
		SUPPORTED_ENCRYPTION_METHODS = methods;
	}


	/**
	 * The content master key (CMK).
	 */
	protected final SecretKey cmk;


	/**
	 * Creates a new direct encryption / decryption provider.
	 *
	 * @param key The shared symmetric key. Must be 128 bits (16 bytes),
	 *            256 bits (32 bytes) or 512 bits (64 bytes) long. Must not 
	 *            be {@code null}.
	 */
	protected DirectCryptoProvider(final byte[] key)
		throws JOSEException {

		super(SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);

		if (key.length != 16 && key.length != 32 && key.length != 64) {

			throw new JOSEException("The key length must be 128 bits (16 bytes), 256 bits (32 bytes) or 512 bites (64 bytes)");
		}

		cmk = new SecretKeySpec(key, "AES");
	}


	/**
	 * Gets the shared symmetric key.
	 *
	 * @return The key.
	 */
	public byte[] getKey() {

		return cmk.getEncoded();
	}
}
