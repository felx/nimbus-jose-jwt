package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;


/**
 * Static methods for Hash-based Message Authentication Codes (HMAC). This
 * class is thread-safe.
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-01-28)
 */
@ThreadSafe
class HMAC {


	/**
	 * Computes a Hash-based Message Authentication Code (HMAC) for the
	 * specified (shared) secret and message.
	 *
	 * @param alg      The Java Cryptography Architecture (JCA) HMAC
	 *                 algorithm name. Must not be {@code null}.
	 * @param secret   The (shared) secret. Must not be {@code null}.
	 * @param message  The message. Must not be {@code null}.
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 *
	 * @return A MAC service instance.
	 *
	 * @throws JOSEException If the algorithm is not supported or the
	 *                       MAC secret key is invalid.
	 */
	public static byte[] compute(final String alg,
				     final byte[] secret,
				     final byte[] message,
				     final Provider provider)
		throws JOSEException {

		return compute(new SecretKeySpec(secret, alg), message, provider);
	}


	/**
	 * Computes a Hash-based Message Authentication Code (HMAC) for the
	 * specified (shared) secret key and message.
	 *
	 * @param secretKey The (shared) secret key, with the appropriate HMAC
	 *                  algorithm. Must not be {@code null}.
	 * @param message   The message. Must not be {@code null}.
	 * @param provider  The JCA provider, or {@code null} to use the
	 *                  default one.
	 *
	 * @return A MAC service instance.
	 *
	 * @throws JOSEException If the algorithm is not supported or the MAC 
	 *                       secret key is invalid.
	 */
	public static byte[] compute(final SecretKey secretKey,
				     final byte[] message,
				     final Provider provider)
		throws JOSEException {

		Mac mac;

		try {
			if (provider != null) {
				mac = Mac.getInstance(secretKey.getAlgorithm(), provider);
			} else {
				mac = Mac.getInstance(secretKey.getAlgorithm());
			}

			mac.init(secretKey);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException("Unsupported HMAC algorithm: " + e.getMessage(), e);

		} catch (InvalidKeyException e) {

			throw new JOSEException("Invalid HMAC key: " + e.getMessage(), e);
		}

		mac.update(message);

		return mac.doFinal();
	}
}
