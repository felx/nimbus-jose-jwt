package com.nimbusds.jose.crypto;


import java.security.Provider;

import net.jcip.annotations.Immutable;


/**
 * Pseudo-Random Function (PRF) parameters, intended for use in the Password-
 * Based Key Derivation Function 2 (PBKDF2).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-24)
 */
@Immutable
final class PRFParams {


	/**
	 * The JCA MAC algorithm name.
	 */
	private final String jcaMacAlg;


	/**
	 * The JCA MAC provider, {@code null} to use the default one.
	 */
	private final Provider macProvider;


	/**
	 * The byte length of the key to derive.
	 */
	private final int dkLen;


	/**
	 * Creates a new pseudo-random function parameters instance.
	 *
	 * @param jcaMacAlg   The JCA MAC algorithm name. Must not be
	 *                    {@code null}.
	 * @param macProvider The JCA MAC provider, {@code null} to use the
	 *                    default one.
	 * @param dkLen       The byte length of the key to derive.

	 */
	public PRFParams(String jcaMacAlg, Provider macProvider, int dkLen) {
		this.jcaMacAlg = jcaMacAlg;
		this.macProvider = macProvider;
		this.dkLen = dkLen;
	}


	/**
	 * Returns the JCA MAC algorithm name.
	 *
	 * @return The JCA MAC algorithm name.
	 */
	public String getMACAlgorithm() {

		return jcaMacAlg;
	}


	/**
	 * Returns the JCA MAC provider.
	 *
	 * @return The JCA MAC provider, {@code null} to use the default one.
	 */
	public Provider getMacProvider() {

		return macProvider;
	}


	/**
	 * Returns the byte length of the key to derive.
	 *
	 * @return The byte length of the key to derive.
	 */
	public int getDerivedKeyByteLength() {

		return dkLen;
	}
}
