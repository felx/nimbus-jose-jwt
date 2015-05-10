package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;


/**
 * The base abstract class for Elliptic Curve Diffie-Hellman encrypters and
 * decrypters of {@link com.nimbusds.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A256KW}
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-09)
 */
abstract class ECDHCryptoProvider {


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
	public static final Map<Integer, Set<JWEAlgorithm>> COMPATIBLE_ALGORITHMS;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {

		Set<JWEAlgorithm> algs = new HashSet<>();
		algs.add(JWEAlgorithm.ECDH_ES);
		algs.add(JWEAlgorithm.ECDH_ES_A128KW);
		algs.add(JWEAlgorithm.ECDH_ES_A192KW);
		algs.add(JWEAlgorithm.ECDH_ES_A256KW);
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

		COMPATIBLE_ALGORITHMS = null; // TODO
	}

}