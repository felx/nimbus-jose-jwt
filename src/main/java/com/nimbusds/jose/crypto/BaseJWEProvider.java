package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEProvider;
import com.nimbusds.jose.jca.JWEJCAProviderAware;
import com.nimbusds.jose.jca.JWEJCAProviderSpec;


/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and 
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
abstract class BaseJWEProvider implements JWEProvider, JWEJCAProviderAware {


	/**
	 * The supported algorithms by the JWE provider intance.
	 */
	private final Set<JWEAlgorithm> algs;


	/**
	 * The supported encryption methods by the JWE provider instance.
	 */
	private final Set<EncryptionMethod> encs;


	/**
	 * The JWE JCA provider specification.
	 */
	private JWEJCAProviderSpec jcaProviderSpec = new JWEJCAProviderSpec();


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
	public void setJWEJCAProvider(final JWEJCAProviderSpec jcaProviderSpec) {

		if (jcaProviderSpec == null) {
			throw new IllegalArgumentException("The JCA provider specification must not be null");
		}

		this.jcaProviderSpec = jcaProviderSpec;
	}


	@Override
	public JWEJCAProviderSpec getJWEJCAProvider() {

		return jcaProviderSpec;
	}
}

