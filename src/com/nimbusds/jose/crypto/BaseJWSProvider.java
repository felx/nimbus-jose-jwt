package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSAlgorithmProvider;


/**
 * The base abstract class for JSON Web Signature (JWS) signers and verifiers.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
abstract class BaseJWSProvider implements JWSAlgorithmProvider {


	/**
	 * The supported algorithms.
	 */
	private Set<JWSAlgorithm> algs;
	
	
	/**
	 * Creates a new base JWS provider.
	 *
	 * @param algs The supported JWS algorithms. Must not be {@code null}.
	 */
	public BaseJWSProvider(final Set<JWSAlgorithm> algs) {
	
		if (algs == null)
			throw new IllegalArgumentException("The supported JWS algorithm set must not be null");
		
		this.algs = Collections.unmodifiableSet(algs);
	}
	
	
	@Override
	public Set<JWSAlgorithm> supportedAlgorithms() {
	
		return algs;
	}
}

