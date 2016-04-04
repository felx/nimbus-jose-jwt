package com.nimbusds.jose.crypto.bc;


import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * BouncyCastle JCA provider singleton, intended to prevent memory leaks by
 * ensuring a single instance is loaded at all times. Application code that
 * needs a BouncyCastle JCA provider should use the {@link #getInstance()}
 * method to obtain an instance.
 *
 * @author Vladimir Dzhuvinov
 */
public final class BouncyCastleProviderSingleton {


	/**
	 * The BouncyCastle provider, lazily instantiated.
	 */
	private static BouncyCastleProvider bouncyCastleProvider;


	/**
	 * Prevents external instantiation.
	 */
	private BouncyCastleProviderSingleton() { }


	/**
	 * Returns a BouncyCastle JCA provider instance.
	 *
	 * @return The BouncyCastle JCA provider instance.
	 */
	public static BouncyCastleProvider getInstance() {

		if (bouncyCastleProvider != null) {

			return bouncyCastleProvider;

		} else {
			bouncyCastleProvider = new BouncyCastleProvider();
			return bouncyCastleProvider;
		}
	}
}
