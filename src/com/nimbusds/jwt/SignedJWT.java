package com.nimbusds.jwt;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.sdk.JOSEObject;
import com.nimbusds.jose.sdk.Payload;
import com.nimbusds.jose.sdk.JWSHeader;
import com.nimbusds.jose.sdk.JWSObject;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Signed JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public class SignedJWT extends JWSObject implements JWT {


	/**
	 * Creates a new to-be-signed JSON Web Token (JWT) with the specified
	 * header and claims set. The initial state will be 
	 * {@link com.nimbusds.jose.sdk.JWSObject.State#UNSIGNED unsigned}.
	 *
	 * @param header    The JWS header. Must not be {@code null}.
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public SignedJWT(final JWSHeader header, final ClaimsSet claimsSet) {
	
		super(header, new Payload(claimsSet.toJSONObject()));
	}
	
	
	/**
	 * Creates a new signed JSON Web Token (JWT) with the specified 
	 * serialised parts. The state will be 
	 * {@link com.nimbusds.jose.sdk.JWSObject.State#SIGNED signed}.
	 *
	 * @param firstPart  The first part, corresponding to the JWS header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the claims set
	 *                   (payload). Must not be {@code null}.
	 * @param thirdPart  The third part, corresponding to the signature.
	 *                   Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public SignedJWT(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart)	
		throws ParseException {
	
		super(firstPart, secondPart, thirdPart);
	}
	
	
	@Override
	public ReadOnlyClaimsSet getClaimsSet()	
		throws ParseException {
	
		JSONObject json = getPayload().toJSONObject();
		
		if (json == null)
			throw new ParseException("Payload of JWS object is not a valid JSON object", 0);
		
		return ClaimsSet.parse(json);
	}
	
	
	/**
	 * Parses a signed JSON Web Token (JWT) from the specified string in 
	 * compact format. 
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The signed JWT.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        signed JWT.
	 */
	public static SignedJWT parse(final String s)
		throws ParseException {
		
		Base64URL[] parts = JOSEObject.split(s);
		
		if (parts.length != 3)
			throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
		
		return new SignedJWT(parts[0], parts[1], parts[2]);
	}
}
