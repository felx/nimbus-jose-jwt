package com.nimbusds.jwt;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Parser for unsecured (plain), signed and encrypted JSON Web Tokens (JWTs).
 *
 * @author Vladimir Dzhuvinov
 * @author Junya Hayashi
 * @version 2015-06-14
 */
public final class JWTParser {


	/**
	 * Parses an unsecured (plain), signed or encrypted JSON Web Token
	 * (JWT) from the specified string in compact format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The corresponding {@link PlainJWT}, {@link SignedJWT} or
	 *         {@link EncryptedJWT} instance.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        unsecured, signed or encrypted JWT.
	 */
	public static JWT parse(final String s)
		throws ParseException {

		final int firstDotPos = s.indexOf(".");
		
		if (firstDotPos == -1)
			throw new ParseException("Invalid JWT serialization: Missing dot delimiter(s)", 0);
			
		Base64URL header = new Base64URL(s.substring(0, firstDotPos));
		
		JSONObject jsonObject;

		try {
			jsonObject = JSONObjectUtils.parseJSONObject(header.decodeToString());

		} catch (ParseException e) {

			throw new ParseException("Invalid unsecured/JWS/JWE header: " + e.getMessage(), 0);
		}

		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (alg.equals(Algorithm.NONE)) {
			return PlainJWT.parse(s);
		} else if (alg instanceof JWSAlgorithm) {
			return SignedJWT.parse(s);
		} else if (alg instanceof JWEAlgorithm) {
			return EncryptedJWT.parse(s);
		} else {
			throw new AssertionError("Unexpected algorithm type: " + alg);
		}
	}


	/**
	 * Prevents instantiation.
	 */
	private JWTParser() {

	}
}
