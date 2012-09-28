package com.nimbusds.jwt;


import java.text.ParseException;

import com.nimbusds.jose.sdk.ReadOnlyHeader;


/**
 * JSON Web Token (JWT) interface.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public interface JWT {


	/**
	 * Gets the JOSE header of the JSON Web Token (JWT).
	 *
	 * @return The header.
	 */
	public ReadOnlyHeader getHeader();
	
	 
	/**
	 * Gets the claims set of the JSON Web Token (JWT).
	 *
	 * @return The claims set, {@code null} if not available (for an 
	 *         encrypted JWT that isn't decrypted).
	 *
	 * @throws ParseException If payload of the plain/JWS/JWE object doesn't
	 *                        represent a valid JSON object and a JWT claims
	 *                        set.
	 */
	public ReadOnlyClaimsSet getClaimsSet()
		throws ParseException;
	
	
	/**
	 * Serialises the JSON Web Token (JWT) to its compact format consisting 
	 * of Base64URL-encoded parts delimited by period ('.') characters.
	 *
	 * @return The serialised JWT.
	 *
	 * @throws IllegalStateException If the JOSE object is not in a state 
	 *                               that permits serialisation.
	 */
	public String serialize();
}
