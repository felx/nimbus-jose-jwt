package com.nimbusds.jose;


import java.security.Provider;


/**
 * The base abstract JCA provider specification for {@link AlgorithmProvider
 * JOSE algorithm provider} implementations.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
public abstract class JCAProviderSpec {


	/**
	 * The JCA provider for all operations.
	 */
	private Provider provider;


	/**
	 * Creates a new base abstract JCA provider specification.
	 *
	 * @param provider The specific JCA provider to be used for all
	 *                 operations, {@code null} to use the default one.
	 */
	protected JCAProviderSpec(final Provider provider) {

		this.provider = provider;
	}


	/**
	 * Gets the specific JCA provider to be used for all operations.
	 *
	 * @return The JCA provider, {@code null} implies the default one.
	 */
	public Provider getProvider() {

		return provider;
	}
}
