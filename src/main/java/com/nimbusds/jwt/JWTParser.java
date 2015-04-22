package com.nimbusds.jwt;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.Context;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.proc.JWTHandler;


/**
 * Parser for plain, signed and encrypted JSON Web Tokens (JWTs).
 *
 * @author Vladimir Dzhuvinov
 * @author Junya Hayashi
 * @version $version$ (2015-04-22)
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

		final int firstDotPos = s.indexOf(".");
		
		if (firstDotPos == -1)
			throw new ParseException("Invalid JWT serialization: Missing dot delimiter(s)", 0);
			
		Base64URL header = new Base64URL(s.substring(0, firstDotPos));
		
		JSONObject jsonObject;

		try {
			jsonObject = JSONObjectUtils.parseJSONObject(header.decodeToString());

		} catch (ParseException e) {

			throw new ParseException("Invalid plain/JWS/JWE header: " + e.getMessage(), 0);
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
	 * Parses a plain, signed or encrypted JSON Web Token (JWT) from the
	 * specified string in compact format.
	 *
	 * @param s       The string to parse. Must not be {@code null}.
	 * @param handler Handler for the parsed JWT. Must not be {@code null}.
	 * @param context Optional context of the JWT, {@code null} if not
	 *                required.
	 *
	 * @return The object returned by the handler, {@code null} if none is
	 *         returned.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        plain, signed or encrypted JWT.
	 */
	public static <T, C extends Context> T parse(final String s, final JWTHandler<T,C> handler, final C context)
		throws ParseException {

		JWT jwt = parse(s);

		if (jwt instanceof PlainJWT) {
			return handler.onPlainJWT((PlainJWT)jwt, context);
		} else if (jwt instanceof SignedJWT) {
			return handler.onSignedJWT((SignedJWT)jwt, context);
		} else {
			return handler.onEncryptedJWT((EncryptedJWT)jwt, context);
		}
	}


	/**
	 * Prevents instantiation.
	 */
	private JWTParser() {

	}
}
