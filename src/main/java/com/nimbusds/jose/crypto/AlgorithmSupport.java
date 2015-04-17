package com.nimbusds.jose.crypto;


import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;


/**
 * JOSE algorithm support.
 */
class AlgorithmSupport {


	/**
	 * Ensures the specified JWS algorithm is supported.
	 *
	 * @param supportedAlgs The supported JWS algorithms. Must not be
	 *                      {@code null}.
	 * @param alg           The JWS algorithm to check. Must not be
	 *                      {@code null}.
	 *
	 * @throws IllegalArgumentException If the algorithm is not supported.
	 */
	public static void ensure(final Set<JWSAlgorithm> supportedAlgs, final JWSAlgorithm alg) {

		if (! supportedAlgs.contains(alg)) {
			throw new IllegalArgumentException("Unsupported JWS algorithm: " + alg);
		}
	}
}
