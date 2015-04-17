package com.nimbusds.jose;


import java.security.Provider;

import net.jcip.annotations.Immutable;


/**
 * The JCA provider specification for {@link JWSAlgorithmProvider JWS algorithm
 * provider} implementations.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
@Immutable
public final class JWSJCAProviderSpec extends JCAProviderSpec {


	/**
	 * Creates a new JCA provider specification for JWS.
	 *
	 * @param provider The specific JCA provider to be used for all
	 *                 operations, {@code null} to use the default one.
	 */
	private JWSJCAProviderSpec(final Provider provider) {

		super(provider);
	}


	/**
	 * Creates a new default JCA provider specification for JWS.
	 */
	public JWSJCAProviderSpec() {

		super(null);
	}


	/**
	 * Sets the specific JCA provider to be used for all operations.
	 *
	 * @param provider The specific JCA provider to be used for all
	 *                 operations, {@code null} to use the default one.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWSJCAProviderSpec withProvider(final Provider provider) {

		return new JWSJCAProviderSpec(provider);
	}
}
