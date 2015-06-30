package com.nimbusds.jose.crypto;


/**
 * Array utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-09-01
 */
class ConstantTimeUtils {


	/**
	 * Checks the specified arrays for equality in constant time. Intended
	 * to mitigate timing attacks.
	 *
	 * @param a The first array. Must not be {@code null}.
	 * @param b The second array. Must not be {@code null}.
	 *
	 * @return {@code true} if the two arrays are equal, else
	 *         {@code false}.
	 */
	public static boolean areEqual(final byte[] a, final byte[] b) {

		// From http://codahale.com/a-lesson-in-timing-attacks/

		if (a.length != b.length) {
			return false;
		}

		int result = 0;
		for (int i = 0; i < a.length; i++) {
			result |= a[i] ^ b[i];
		}

		return result == 0;
	}


	/**
	 * Prevents public instantiation.
	 */
	private ConstantTimeUtils() { }
}
