package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

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
 * @version $version$ (2015-05-16)
 */
abstract class DirectCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {
		Set<JWEAlgorithm> algs = new HashSet<>();
		algs.add(JWEAlgorithm.DIR);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * The Content Encryption Key (CEK).
	 */
	private final SecretKey cek;


	/**
	 * Creates a new direct encryption / decryption provider.
	 *
	 * @param cek The Content Encryption Key. Must be 128 bits (16 bytes),
	 *            192 bits (24 bytes), 256 bits (32 bytes), 384 bits (48
	 *            bytes) or 512 bits (64 bytes) long. Must not be
	 *            {@code null}.
	 */
	protected DirectCryptoProvider(final SecretKey cek) {

		super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

		byte[] keyBytes = cek.getEncoded();

		if (keyBytes.length != 16 &&
		    keyBytes.length != 24 &&
		    keyBytes.length != 32 &&
		    keyBytes.length != 48 &&
		    keyBytes.length != 64) {

			throw new IllegalArgumentException("The Content Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384 bits (48 bytes) or 512 bites (64 bytes)");
		}

		this.cek = cek;
	}


	/**
	 * Gets the Content Encryption Key (CEK).
	 *
	 * @return The key.
	 */
	public SecretKey getKey() {

		return cek;
	}
}
