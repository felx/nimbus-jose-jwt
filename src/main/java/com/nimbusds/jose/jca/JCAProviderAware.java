package com.nimbusds.jose.jca;


import java.security.Provider;


/**
 * Interface for setting a Java Cryptography Architecture (JCA) {@link Provider
 * provider}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-20)
 */
public interface JCAProviderAware {


	/**
	 * Sets a JCA provider (for all or selected cryptographic operations).
	 *
	 * @param jcaProviderSpec The JCA provider, {@code null} if not
	 *                        specified.
	 */
	void setJCAProvider(final Provider jcaProviderSpec);


	/**
	 * Returns the JCA provider (for all or selected cryptographic
	 * operations).
	 *
	 * @return The JCA provider, {@code null} if not specified.
	 */
	Provider getJCAProvider();
}
