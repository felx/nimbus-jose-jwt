package com.nimbusds.jwt;


import java.text.ParseException;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.PlainObject;

import com.nimbusds.util.Base64URL;


/**
 * Plain JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-22)
 */
public class PlainJWT extends PlainObject implements JWT {


	/**
	 * Creates a new plain JSON Web Token (JWT) with a default 
	 * {@link com.nimbusds.jose.PlainHeader} and the specified claims set.
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
	public ClaimsSet getClaimsSet() {
	
		return null;
	}
}
