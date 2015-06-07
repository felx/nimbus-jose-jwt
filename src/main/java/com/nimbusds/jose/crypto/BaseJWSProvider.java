package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSProvider;
import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.jca.JCAContext;


/**
 * The base abstract class for JSON Web Signature (JWS) signers and verifiers.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-02)
 */
abstract class BaseJWSProvider implements JWSProvider, JCAAware<JCAContext> {


	/**
	 * The supported algorithms by the JWS provider instance.
	 */
	private final Set<JWSAlgorithm> algs;


	/**
	 * The JCA context.
	 */
	private JCAContext jcaContext = new JCAContext();


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
	public void setJCAContext(final JCAContext jcaContext) {

		if (jcaContext == null) {
			throw new IllegalArgumentException("The JCA context must not be null");
		}

		this.jcaContext = jcaContext;
	}


	@Override
	public JCAContext getJCAContext() {

		return jcaContext;
	}
}

