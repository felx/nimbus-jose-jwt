package com.nimbusds.jwt;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.sdk.JOSEObject;
import com.nimbusds.jose.sdk.Payload;
import com.nimbusds.jose.sdk.PlainHeader;
import com.nimbusds.jose.sdk.PlainObject;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Plain JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public class PlainJWT extends PlainObject implements JWT {


	/**
	 * Creates a new plain JSON Web Token (JWT) with a default 
	 * {@link com.nimbusds.jose.sdk.PlainHeader} and the specified claims 
	 * set.
	 *
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public PlainJWT(final ClaimsSet claimsSet) {
		
		super(new Payload(claimsSet.toJSONObject()));
	}
	
	
	/**
	 * Creates a new plain JSON Web Token (JWT) with the specified header 
	 * and claims set.
	 *
	 * @param header    The plain header. Must not be {@code null}.
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public PlainJWT(final PlainHeader header, ClaimsSet claimsSet) {
			
		super(header, new Payload(claimsSet.toJSONObject()));
	}
	
	
	/**
	 * Creates a new plain JSON Web Token (JWT) with the specified 
	 * Base64URL-encoded parts.
	 *
	 * @param firstPart  The first part, corresponding to the plain header. 
	 *                   Must not be {@code null}.
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
	public ReadOnlyClaimsSet getClaimsSet()
		throws ParseException {
	
		JSONObject json = getPayload().toJSONObject();
		
		if (json == null)
			throw new ParseException("Payload of plain JOSE object is not a valid JSON object", 0);
		
		return ClaimsSet.parse(json);
	}
	
	
	/**
	 * Parses a plain JSON Web Token (JWT) from the specified string in 
	 * compact format. 
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The plain JWT.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        plain JWT.
	 */
	public static PlainJWT parse(final String s)
		throws ParseException {
		
		Base64URL[] parts = JOSEObject.split(s);
		
		if (! parts[2].toString().isEmpty())
			throw new ParseException("Unexpected third Base64URL part", 0);
		
		return new PlainJWT(parts[0], parts[1]);
	}
}
