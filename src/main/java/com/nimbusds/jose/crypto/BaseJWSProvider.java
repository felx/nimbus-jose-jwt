package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSAlgorithmProvider;
import com.nimbusds.jose.JWSJCAProviderSpec;


/**
 * The base abstract class for JSON Web Signature (JWS) signers and verifiers.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
abstract class BaseJWSProvider implements JWSAlgorithmProvider {


	/**
	 * The supported algorithms.
	 */
	private final Set<JWSAlgorithm> algs;


	/**
	 * The JCA provider specification, {@code null} implies the default
	 * one.
	 */
	private final JWSJCAProviderSpec jcaSpec;


	/**
	 * Creates a new base JWS provider.
	 *
	 * @param algs    The supported JWS algorithms. Must not be
	 *                {@code null}.
	 * @param jcaSpec The JCA provider specification, {@code null} implies
	 *                the default one.
	 */
	public BaseJWSProvider(final Set<JWSAlgorithm> algs,
			       final JWSJCAProviderSpec jcaSpec) {

		if (algs == null || algs.isEmpty()) {
			throw new IllegalArgumentException("The supported JWS algorithm set must not be null or empty");
		}

		this.algs = Collections.unmodifiableSet(algs);

		this.jcaSpec = jcaSpec;
	}


	@Override
	public Set<JWSAlgorithm> supportedAlgorithms() {

		return algs;
	}


	@Override
	public JWSJCAProviderSpec getJCAProviderSpec() {

		return jcaSpec;
	}
}

