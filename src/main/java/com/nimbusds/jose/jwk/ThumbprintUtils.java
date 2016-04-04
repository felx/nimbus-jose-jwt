package com.nimbusds.jose.jwk;


import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;


/**
 * Thumbprint utilities.
 *
 * <p>See RFC 7638.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-09-28
 */
public final class ThumbprintUtils {


	/**
	 * Computes the SHA-256 thumbprint for the specified JWK.
	 *
	 * @param jwk The JWK. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint.
	 *
	 * @throws JOSEException If the SHA-256 hash algorithm is not
	 *                       supported.
	 */
	public static Base64URL compute(final JWK jwk)
		throws JOSEException {

		return compute("SHA-256", jwk);
	}


	/**
	 * Computes the thumbprint for the specified JWK.
	 *
	 * @param hashAlg The hash algorithm. Must not be {@code null}.
	 * @param jwk     The JWK. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint.
	 *
	 * @throws JOSEException If the hash algorithm is not supported.
	 */
	public static Base64URL compute(final String hashAlg, final JWK jwk)
		throws JOSEException {

		final LinkedHashMap<String,?> orderedParams = jwk.getRequiredParams();

		return compute(hashAlg, orderedParams);
	}


	/**
	 * Computes the thumbprint for the specified required JWK parameters.
	 *
	 * @param hashAlg The hash algorithm. Must not be {@code null}.
	 * @param params  The required JWK parameters, alphanumerically sorted
	 *                by parameter name and ready for JSON object
	 *                serialisation. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint.
	 *
	 * @throws JOSEException If the hash algorithm is not supported.
	 */
	public static Base64URL compute(final String hashAlg, final LinkedHashMap<String,?> params)
		throws JOSEException {

		final String json = JSONObject.toJSONString(params);

		final MessageDigest md;

		try {
			md = MessageDigest.getInstance(hashAlg);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException("Couldn't compute JWK thumbprint: Unsupported hash algorithm: " + e.getMessage(), e);
		}

		md.update(json.getBytes(Charset.forName("UTF-8")));

		return Base64URL.encode(md.digest());
	}
}
