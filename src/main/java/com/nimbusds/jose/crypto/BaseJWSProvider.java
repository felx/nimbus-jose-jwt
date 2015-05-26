package com.nimbusds.jose.crypto;


import java.security.Provider;
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSProvider;
import com.nimbusds.jose.jca.JCAProviderAware;


/**
 * The base abstract class for JSON Web Signature (JWS) signers and verifiers.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
abstract class BaseJWSProvider implements JWSProvider, JCAProviderAware {


	/**
	 * The supported algorithms by the JWS provider instance.
	 */
	private final Set<JWSAlgorithm> algs;


	/**
	 * The JCA provider, {@code null} implies the default one.
	 */
	private Provider jcaProvider;


	/**
	 * Creates a new base JWS provider.
	 *
	 * @param algs The supported algorithms by the JWS provider instance.
	 *             Must not be {@code null}.
	 */
	public BaseJWSProvider(final Set<JWSAlgorithm> algs) {

		if (algs == null) {
			throw new IllegalArgumentException("The supported JWS algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);
	}


	@Override
	public Set<JWSAlgorithm> supportedJWSAlgorithms() {

		return algs;
	}


	@Override
	public void setJCAProvider(final Provider jcaProvider) {

		this.jcaProvider = jcaProvider;
	}


	@Override
	public Provider getJCAProvider() {

		return jcaProvider;
	}
}

