package com.nimbusds.jose.crypto;


import java.util.Collections;
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-11-25)
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
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

		Set<EncryptionMethod> methods = new HashSet<EncryptionMethod>();
		methods.add(EncryptionMethod.A128CBC_HS256);
		methods.add(EncryptionMethod.A192CBC_HS384);
		methods.add(EncryptionMethod.A256CBC_HS512);
		methods.add(EncryptionMethod.A128GCM);
		methods.add(EncryptionMethod.A192GCM);
		methods.add(EncryptionMethod.A256GCM);
		SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(methods);
	}


	/**
	 * The Content Encryption Key (CEK).
	 */
	private final SecretKey cek;


	/**
	 * Creates a new direct encryption / decryption provider.
	 *
	 * @param key The shared symmetric key. Its algorithm must be "AES".
	 *            Must be 128 bits (16 bytes), 192 bits (24 bytes), 256
	 *            bits (32 bytes), 384 bits (48 bytes) or 512 bits
	 *            (64 bytes) long. Must not be {@code null}.
	 */
	protected DirectCryptoProvider(final SecretKey key)
		throws JOSEException {

		super(SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);

		if (! key.getAlgorithm().equals("AES")) {

			throw new JOSEException("The algorithm of the shared symmetric key must be AES");
		}
		

		byte[] keyBytes = key.getEncoded();

		if (keyBytes.length != 16 &&
		    keyBytes.length != 24 &&
		    keyBytes.length != 32 &&
		    keyBytes.length != 48 &&
		    keyBytes.length != 64) {

			throw new JOSEException("The length of the shared symmetric key must be 128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384 bits (48 bytes) or 512 bites (64 bytes)");
		}

		cek = key;
	}


	/**
	 * Creates a new direct encryption / decryption provider.
	 *
	 * @param keyBytes The shared symmetric key, as a byte array. Must be 
	 *                 128 bits (16 bytes), 256 bits (32 bytes) or 512 bits
	 *                 (64 bytes) long. Must not be {@code null}.
	 */
	protected DirectCryptoProvider(final byte[] keyBytes)
		throws JOSEException {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Gets the shared symmetric key.
	 *
	 * @return The key.
	 */
	public SecretKey getKey() {

		return cek;
	}
}
