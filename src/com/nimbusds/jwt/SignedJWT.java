package com.nimbusds.jwt;


import java.text.ParseException;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;

import com.nimbusds.util.Base64URL;


/**
 * Signed JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-22)
 */
public class SignedJWT extends JWSObject implements JWT {


	/**
	 * Creates a new to-be-signed JSON Web Token (JWT) with the specified
	 * header and claims set. The initial state will be 
	 * {@link com.nimbusds.jose.JWSObject.State#UNSIGNED unsigned}.
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
	 * {@link com.nimbusds.jose.JWSObject.State#SIGNED signed}.
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
	public ClaimsSet getClaimsSet() {
	
		return null;
	}
}
