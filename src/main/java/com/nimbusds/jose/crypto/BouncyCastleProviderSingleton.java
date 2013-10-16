package com.nimbusds.jose.crypto;


import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * BouncyCastle provider singleton. Intended to guard against memory leaks. All
 * JOSE+JWT code that makes use of BouncyCastle's JCE provider must use this
 * singleton class to obtain an instance.
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
	 * Returns a BouncyCastle provider instance.
	 *
	 * @return The BouncyCastle provider instance.
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
