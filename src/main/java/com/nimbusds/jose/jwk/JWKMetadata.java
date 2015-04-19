package com.nimbusds.jose.jwk;


import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;


/**
 * JSON Web Key (JWK) metadata.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-19)
 */
final class JWKMetadata {


	/**
	 * Parses the JWK type.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key type.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static KeyType parseKeyType(final JSONObject o)
		throws ParseException {

		return KeyType.parse(JSONObjectUtils.getString(o, "kty"));
	}


	/**
	 * Parses the optional public key use.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key use, {@code null} if not specified or if the key is
	 *         intended for signing as well as encryption.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static KeyUse parseKeyUse(final JSONObject o)
		throws ParseException {

		if (o.containsKey("use")) {
			return KeyUse.parse(JSONObjectUtils.getString(o, "use"));
		} else {
			return null;
		}
	}


	/**
	 * Parses the optional key operations.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key operations, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Set<KeyOperation> parseKeyOperations(final JSONObject o)
		throws ParseException {
		
		if(o.containsKey("key_ops")) {
			return KeyOperation.parse(JSONObjectUtils.getStringList(o, "key_ops"));
		} else {
			return null;
		}
	}


	/**
	 * Parses the optional algorithm.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return  The intended JOSE algorithm, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Algorithm parseAlgorithm(final JSONObject o)
		throws ParseException {

		if (o.containsKey("alg")) {
			return new Algorithm(JSONObjectUtils.getString(o, "alg"));
		} else {
			return null;
		}
	}


	/**
	 * Parses the optional key ID.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key ID, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static String parseKeyID(final JSONObject o)
		throws ParseException {

		if (o.containsKey("kid")) {
			return JSONObjectUtils.getString(o, "kid");
		} else {
			return null;
		}
	}


	/**
	 * Parses the optional X.509 certificate URL.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate URL, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static URI parseX509CertURL(final JSONObject o)
		throws ParseException {

		if (o.containsKey("x5u")) {
			return JSONObjectUtils.getURI(o, "x5u");
		} else {
			return null;
		}
	}


	/**
	 * Parses the optional X.509 certificate thumbprint.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate thumbprint, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Base64URL parseX509CertThumbprint(final JSONObject o)
		throws ParseException {

		if (o.containsKey("x5t")) {
			return new Base64URL(JSONObjectUtils.getString(o, "x5t"));
		} else {
			return null;
		}
	}


	/**
	 * Parses the optional X.509 certificate chain.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate chain as a unmodifiable list,
	 *         {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static List<Base64> parseX509CertChain(final JSONObject o)
		throws ParseException {

		if (o.containsKey("x5c")) {
			return X509CertChainUtils.parseX509CertChain(JSONObjectUtils.getJSONArray(o, "x5c"));
		} else {
			return null;
		}
	}
}
