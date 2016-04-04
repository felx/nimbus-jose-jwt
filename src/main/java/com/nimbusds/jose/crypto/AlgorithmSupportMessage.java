package com.nimbusds.jose.crypto;


import java.util.Collection;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;


/**
 * Algorithm support messages, intended for JOSE exceptions.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-20
 */
class AlgorithmSupportMessage {


	/**
	 * Itemises the specified collection to human readable string.
	 *
	 * @param collection The collection, with valid {@code toString}
	 *                   methods. Must not be {@code null}.
	 *
	 * @return The string.
	 */
	private static String itemize(final Collection collection) {

		StringBuilder sb = new StringBuilder();

		Object[] items = collection.toArray();

		for (int i=0; i < items.length; i++) {

			if (i == 0) {
				// no delimiter
			} else if (i < items.length - 1) {
				sb.append(", ");
			} else if (i == items.length - 1) {
				sb.append(" or ");
			}

			sb.append(items[i].toString());
		}

		return sb.toString();
	}


	/**
	 * Returns a message that the specified JWS algorithm is not supported.
	 *
	 * @param unsupported The unsupported JWS algorithm. Must not be
	 *                    {@code null}.
	 * @param supported   The supported JWS algorithms. Must not be
	 *                    {@code null}.
	 *
	 * @return The message.
	 */
	public static String unsupportedJWSAlgorithm(final JWSAlgorithm unsupported,
						     final Collection<JWSAlgorithm> supported) {

		return "Unsupported JWS algorithm " + unsupported + ", must be " + itemize(supported);
	}


	/**
	 * Returns a message that the specified JWE algorithm is not supported.
	 *
	 * @param unsupported The unsupported JWE algorithm. Must not be
	 *                    {@code null}.
	 * @param supported   The supported JWE algorithms. Must not be
	 *                    {@code null}.
	 *
	 * @return The message.
	 */
	public static String unsupportedJWEAlgorithm(final JWEAlgorithm unsupported,
						     final Collection<JWEAlgorithm> supported) {

		return "Unsupported JWE algorithm " + unsupported + ", must be " + itemize(supported);
	}


	/**
	 * Returns a message that the specified JWE encryption method is not
	 * supported.
	 *
	 * @param unsupported The unsupported JWE encryption method. Must not
	 *                    be {@code null}.
	 * @param supported   The supported JWE encryption methods. Must not be
	 *                    {@code null}.
	 *
	 * @return The message.
	 */
	public static String unsupportedEncryptionMethod(final EncryptionMethod unsupported,
							 final Collection<EncryptionMethod> supported) {

		return "Unsupported JWE encryption method " + unsupported + ", must be " + itemize(supported);
	}


	/**
	 * Returns a message that the specified elliptic curve is not
	 * supported.
	 *
	 * @param unsupported The unsupported elliptic curve. Must not be
	 *                    {@code null}.
	 * @param supported   The supported elliptic curves. Must not be
	 *                    {@code null}.
	 *
	 * @return The message.
	 */
	public static String unsupportedEllipticCurve(final ECKey.Curve unsupported,
						      final Collection<ECKey.Curve> supported) {

		return "Unsupported elliptic curve " + unsupported + ", must be " + itemize(supported);
	}


	/**
	 * Prevents public instantiation.
	 */
	private AlgorithmSupportMessage() {

	}
}
