package com.nimbusds.jwt;


import java.text.ParseException;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.PlainObject;
import com.nimbusds.jose.util.Base64URL;


/**
 * Unsecured (plain) JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-08-21
 */
@ThreadSafe
public class PlainJWT extends PlainObject implements JWT {


	/**
	 * Creates a new unsecured (plain) JSON Web Token (JWT) with a default
	 * {@link com.nimbusds.jose.PlainHeader} and the specified claims 
	 * set.
	 *
	 * @param claimsSet The JWT claims set. Must not be {@code null}.
	 */
	public PlainJWT(final ReadOnlyJWTClaimsSet claimsSet) {

		super(new Payload(claimsSet.toJSONObject()));
	}


	/**
	 * Creates a new unsecured (plain) JSON Web Token (JWT) with the
	 * specified header and claims set.
	 *
	 * @param header    The unsecured header. Must not be {@code null}.
	 * @param claimsSet The JWT claims set. Must not be {@code null}.
	 */
	public PlainJWT(final PlainHeader header, final ReadOnlyJWTClaimsSet claimsSet) {

		super(header, new Payload(claimsSet.toJSONObject()));
	}


	/**
	 * Creates a new unsecured (plain) JSON Web Token (JWT) with the
	 * specified Base64URL-encoded parts.
	 *
	 * @param firstPart  The first part, corresponding to the unsecured
	 *                   header. Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the claims set 
	 *                   (payload). Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public PlainJWT(final Base64URL firstPart, final Base64URL secondPart)
		throws ParseException {

		super(firstPart, secondPart);
	}


	@Override
	public ReadOnlyJWTClaimsSet getJWTClaimsSet()
		throws ParseException {

		JSONObject json = getPayload().toJSONObject();

		if (json == null) {
			
			throw new ParseException("Payload of unsecured JOSE object is not a valid JSON object", 0);
		}

		return JWTClaimsSet.parse(json);
	}


	/**
	 * Parses an unsecured (plain) JSON Web Token (JWT) from the specified
	 * string in compact format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The unsecured JWT.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        unsecured JWT.
	 */
	public static PlainJWT parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (! parts[2].toString().isEmpty()) {

			throw new ParseException("Unexpected third Base64URL part in the unsecured JWT object", 0);
		}

		return new PlainJWT(parts[0], parts[1]);
	}
}
