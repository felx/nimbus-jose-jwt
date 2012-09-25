package com.nimbusds.jwt;


import java.text.ParseException;


/**
 * JSON Web Token (JWT) interface.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-25)
 */
public interface JWT {


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
}
