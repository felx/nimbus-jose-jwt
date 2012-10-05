package com.nimbusds.jwt;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Parser for plain, signed and encrypted JSON Web Tokens (JWTs).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public final class JWTParser {


	/**
	 * Parses a plain, signed or encrypted JSON Web Token (JWT) from the
	 * specified string in compact format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The corresponding {@link PlainJWT}, {@link SignedJWT} or
	 *         {@link EncryptedJWT} instance.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        plain, signed or encrypted JWT.
	 */
	public static JWT parse(final String s)
		throws ParseException {
		
		Base64URL[] parts = JOSEObject.split(s);

		JSONObject jsonObject = null;

		try {
			jsonObject = JSONObjectUtils.parseJSONObject(parts[0].decodeToString());

		} catch (ParseException e) {

			throw new ParseException("Invalid plain/JWS/JWE header: " + e.getMessage(), 0);
		}

		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (alg.equals(Algorithm.NONE))
			return PlainJWT.parse(s);

		else if (alg instanceof JWSAlgorithm)
			return SignedJWT.parse(s);

		else if (alg instanceof JWEAlgorithm)
			return EncryptedJWT.parse(s);

		else
			throw new AssertionError("Unexpected algorithm type: " + alg);
	}


	/**
	 * Prevents instantiation.
	 */
	private JWTParser() {
	
		// Nothing to do
	}
}
