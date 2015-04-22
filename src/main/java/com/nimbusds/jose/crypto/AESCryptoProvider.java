package com.nimbusds.jose.crypto;


import java.util.*;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;


/**
 * The base abstract class for AES encrypters and decrypters of {@link
 * com.nimbusds.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#A128KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#A192KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#A256KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#A128GCMKW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#A192GCMKW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#A256GCMKW}
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author Melisa Halsband
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-21)
 */
abstract class AESCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * The JWE algorithms compatible with each key size.
	 */
	public static final Map<Integer,Set<JWEAlgorithm>> COMPATIBLE_ALGORITHMS;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {

		Set<JWEAlgorithm> algs = new HashSet<>();
		algs.add(JWEAlgorithm.A128KW);
		algs.add(JWEAlgorithm.A192KW);
		algs.add(JWEAlgorithm.A256KW);
		algs.add(JWEAlgorithm.A128GCMKW);
		algs.add(JWEAlgorithm.A192GCMKW);
		algs.add(JWEAlgorithm.A256GCMKW);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

		Set<EncryptionMethod> methods = new HashSet<>();
		methods.add(EncryptionMethod.A128CBC_HS256);
		methods.add(EncryptionMethod.A192CBC_HS384);
		methods.add(EncryptionMethod.A256CBC_HS512);
		methods.add(EncryptionMethod.A128GCM);
		methods.add(EncryptionMethod.A192GCM);
		methods.add(EncryptionMethod.A256GCM);
		methods.add(EncryptionMethod.A128CBC_HS256_DEPRECATED);
		methods.add(EncryptionMethod.A256CBC_HS512_DEPRECATED);
		SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(methods);


		Map<Integer,Set<JWEAlgorithm>> algsMap = new HashMap<>();
		Set<JWEAlgorithm> bit16Algs = new HashSet<>();
		Set<JWEAlgorithm> bit24Algs = new HashSet<>();
		Set<JWEAlgorithm> bit32Algs = new HashSet<>();
		bit16Algs.add(JWEAlgorithm.A128GCMKW);
		bit16Algs.add(JWEAlgorithm.A128KW);
		bit24Algs.add(JWEAlgorithm.A192GCMKW);
		bit24Algs.add(JWEAlgorithm.A192KW);
		bit32Algs.add(JWEAlgorithm.A256GCMKW);
		bit32Algs.add(JWEAlgorithm.A256KW);
		algsMap.put(16,Collections.unmodifiableSet(bit16Algs));
		algsMap.put(24,Collections.unmodifiableSet(bit24Algs));
		algsMap.put(32,Collections.unmodifiableSet(bit32Algs));
		COMPATIBLE_ALGORITHMS = Collections.unmodifiableMap(algsMap);
	}


	/**
	 * The Key Encryption Key (KEK).
	 */
	private final SecretKey kek;


	/**
	 * Creates a new AES encryption / decryption provider.
	 *
	 *  @param kek The Key Encrypting Key. Must be 128 bits (16 bytes), 192
	 *             bits (24 bytes) or 256 bits (32 bytes). Must not be
	 *             {@code null}.
	 */
	protected AESCryptoProvider(final SecretKey kek) {

		super(SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);

		byte[] keyBytes = kek.getEncoded();

		if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
			throw new IllegalArgumentException("The Key Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes)");
		}

		this.kek = kek;
	}


	/**
	 * Gets the Key Encryption Key (KEK).
	 *
	 * @return The Key Encryption Key.
	 */
	public SecretKey getKey() {

		return kek;
	}


	/**
	 * Returns the JWE algorithms compatible with the key size.
	 *
	 * @return The set of compatible algorithms.
	 */
	public Set<JWEAlgorithm> compatibleJWEAlgorithms() {

		return COMPATIBLE_ALGORITHMS.get(kek.getEncoded().length);
	}
}
