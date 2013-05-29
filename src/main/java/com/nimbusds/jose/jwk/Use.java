package com.nimbusds.jose.jwk;


import java.text.ParseException;


/**
 * Enumeration of key uses. Represents the {@code use} parameter in a JSON Web 
 * Key (JWK).
 *
 * <p>Represents the following JWK use values:
 *
 * <ul>
 *     <li>{@link #SIGNATURE sig}
 *     <li>{@link #ENCRYPTION enc}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-29)
 */
public enum Use {


	/**
	 * Signature.
	 */
	SIGNATURE,


	/**
	 * Encryption.
	 */
	ENCRYPTION;


	/**
	 * Parses a JSON Web Key (JWK) use from the specified {@code use}
	 * parameter value.
	 *
	 * @param s The string to parse. Must be either "sig" or "enc". Must
	 *          not be {@code null}.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        key use.
	 */
	public static Use parse(final String s)
		throws ParseException {

		if (s.equals("sig")) {

			return SIGNATURE;

		} else if (s.equals("enc")) {

			return ENCRYPTION;
		} else {

			throw new ParseException("Invalid JWK use: " + s, 0);
		}
	}
}
