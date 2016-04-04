package com.nimbusds.jose.crypto;


import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;


/**
 * Utility for creating {@link java.security.AlgorithmParameters} objects with
 * an optional JCA provider.
 *
 * @author Justin Richer
 */
class AlgorithmParametersHelper {


	/**
	 * Creates a new {@link java.security.AlgorithmParameters} instance.
	 *
	 * @param name     The name of the requested algorithm. Must not be
	 *                 {@code null}.
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 *
	 * @return The AlgorithmParameters instance.
	 *
	 * @throws NoSuchAlgorithmException If an AlgorithmParameterGeneratorSpi
	 *                                  implementation for the specified
	 *                                  algorithm is not available from the
	 *                                  specified Provider object.
	 */
	public static AlgorithmParameters getInstance(final String name, final Provider provider)
		throws NoSuchAlgorithmException {

		if (provider == null) {
			return AlgorithmParameters.getInstance(name);
		} else {
			return AlgorithmParameters.getInstance(name, provider);
		}
	}
}
