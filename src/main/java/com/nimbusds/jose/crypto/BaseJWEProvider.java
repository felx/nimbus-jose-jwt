package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEAlgorithmProvider;


/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and 
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-22)
 */
abstract class BaseJWEProvider implements JWEAlgorithmProvider {


	/**
	 * The supported algorithms.
	 */
	private final Set<JWEAlgorithm> algs;


	/**
	 * The supported encryption methods.
	 */
	private final Set<EncryptionMethod> encs;


	/**
	 * Creates a new base JWE provider.
	 *
	 * @param algs The supported JWE algorithms. Must not be {@code null}.
	 * @param encs The supported encryption methods. Must not be 
	 *             {@code null}.
	 */
	public BaseJWEProvider(final Set<JWEAlgorithm> algs,
		               final Set<EncryptionMethod> encs) {

		if (algs == null) {
			throw new IllegalArgumentException("The supported JWE algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);


		if (encs == null) {
			throw new IllegalArgumentException("The supported encryption methods must not be null");
		}

		this.encs = encs;
	}


	@Override
	public Set<JWEAlgorithm> supportedAlgorithms() {

		return algs;
	}


	@Override
	public Set<EncryptionMethod> supportedEncryptionMethods() {

		return encs;
	}
}

