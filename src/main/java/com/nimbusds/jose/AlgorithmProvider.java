package com.nimbusds.jose;


/**
 * Common interface for JOSE algorithm providers.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
public interface AlgorithmProvider {


	/**
	 * Returns the JCA provider specification.
	 *
	 * @return The JCA provider specification, {@code null} if not
	 *         specified.
	 */
	public JCAProviderSpec getJCAProviderSpec();
}
