package com.nimbusds.jose;


import java.security.Provider;


/**
 * Common interface for JOSE algorithm providers.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2014-01-28)
 */
public interface AlgorithmProvider {


	/**
	 * Sets a specific JCA provider, to be used for all operations.
	 *
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 */
	public void setProvider(final Provider provider);
}
