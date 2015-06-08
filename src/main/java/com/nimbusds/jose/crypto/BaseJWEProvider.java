package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEProvider;
import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.jca.JWEJCAContext;


/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and 
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-08)
 */
abstract class BaseJWEProvider implements JWEProvider, JCAAware<JWEJCAContext> {


	/**
	 * The supported algorithms by the JWE provider intance.
	 */
	private final Set<JWEAlgorithm> algs;


	/**
	 * The supported encryption methods by the JWE provider instance.
	 */
	private final Set<EncryptionMethod> encs;


	/**
	 * The JWE JCA context.
	 */
	private final JWEJCAContext jcaContext = new JWEJCAContext();


	/**
	 * Creates a new base JWE provider.
	 *
	 * @param algs The supported algorithms by the JWE provider instance.
	 *             Must not be {@code null}.
	 * @param encs The supported encryption methods by the JWE provider
	 *             instance. Must not be {@code null}.
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
	public Set<JWEAlgorithm> supportedJWEAlgorithms() {

		return algs;
	}


	@Override
	public Set<EncryptionMethod> supportedEncryptionMethods() {

		return encs;
	}


	@Override
	public JWEJCAContext getJCAContext() {

		return jcaContext;
	}
}

